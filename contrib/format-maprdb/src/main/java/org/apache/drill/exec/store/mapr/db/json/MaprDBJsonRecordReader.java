/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.drill.exec.store.mapr.db.json;


import com.mapr.db.Table;
import com.mapr.db.Table.TableOption;
import com.mapr.db.exceptions.DBException;
import com.mapr.db.impl.IdCodec;
import com.mapr.db.impl.MapRDBImpl;
import com.mapr.db.index.IndexDesc;
import com.mapr.db.ojai.DBDocumentReaderBase;
import com.mapr.db.util.ByteBufs;
import io.netty.buffer.DrillBuf;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.common.expression.PathSegment;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.exec.ExecConstants;
import org.apache.drill.exec.exception.SchemaChangeException;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.ops.OperatorStats;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.mapr.db.MapRDBFormatPlugin;
import org.apache.drill.exec.store.mapr.db.MapRDBSubScanSpec;
import org.apache.drill.exec.util.EncodedSchemaPathSet;
import org.apache.drill.exec.vector.BaseValueVector;
import org.apache.drill.exec.vector.complex.fn.JsonReaderUtils;
import org.apache.drill.exec.vector.complex.impl.VectorContainerWriter;
import org.apache.hadoop.fs.Path;
import org.ojai.DocumentReader;
import org.ojai.DocumentStream;
import org.ojai.FieldPath;
import org.ojai.FieldSegment;
import org.ojai.store.QueryCondition;
import org.ojai.util.FieldProjector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.apache.drill.shaded.guava.com.google.common.base.Preconditions;
import org.apache.drill.shaded.guava.com.google.common.base.Stopwatch;
import org.apache.drill.shaded.guava.com.google.common.collect.ImmutableSet;
import org.apache.drill.shaded.guava.com.google.common.collect.Iterables;
import org.apache.drill.shaded.guava.com.google.common.collect.Sets;
import org.apache.drill.shaded.guava.com.google.common.base.Predicate;

import com.mapr.db.MapRDB;
import com.mapr.org.apache.hadoop.hbase.util.Bytes;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.TimeUnit;

import static org.apache.drill.exec.store.mapr.PluginConstants.DOCUMENT_SCHEMA_PATH;
import static org.apache.drill.exec.store.mapr.PluginErrorHandler.dataReadError;
import static org.ojai.DocumentConstants.ID_FIELD;

public class MaprDBJsonRecordReader extends AbstractRecordReader {
  private static final Logger logger = LoggerFactory.getLogger(MaprDBJsonRecordReader.class);

  protected static final FieldPath[] ID_ONLY_PROJECTION = { ID_FIELD };

  protected Table table;
  protected QueryCondition condition;

  /**
   * A set of projected FieldPaths that are pushed into MapR-DB Scanner.
   * This set is a superset of the fields returned by {@link #getColumns()} when
   * projection pass-through is in effect. In such cases, {@link #getColumns()}
   * returns only those fields which are required by Drill to run its operators.
   */
  private FieldPath[] scannedFields;

  private OperatorContext operatorContext;
  protected VectorContainerWriter vectorWriter;
  private DBDocumentReaderBase reader;

  private DrillBuf buffer;

  private DocumentStream documentStream;

  private Iterator<DocumentReader> documentReaderIterators;

  private boolean includeId;
  private boolean idOnly;

  private boolean projectWholeDocument;
  private FieldProjector projector;

  private final boolean unionEnabled;
  private final boolean readNumbersAsDouble;
  private boolean disablePushdown;
  private final boolean allTextMode;
  private final boolean ignoreSchemaChange;
  private final boolean disableCountOptimization;
  private final boolean nonExistentColumnsProjection;

  protected final MapRDBSubScanSpec subScanSpec;
  protected final MapRDBFormatPlugin formatPlugin;

  protected OjaiValueWriter valueWriter;
  protected DocumentReaderVectorWriter documentWriter;
  protected int maxRecordsToRead = -1;

  public MaprDBJsonRecordReader(MapRDBSubScanSpec subScanSpec, MapRDBFormatPlugin formatPlugin,
                                List<SchemaPath> projectedColumns, FragmentContext context, int maxRecords) {
    this(subScanSpec, formatPlugin, projectedColumns, context);
    this.maxRecordsToRead = maxRecords;
  }

  protected MaprDBJsonRecordReader(MapRDBSubScanSpec subScanSpec, MapRDBFormatPlugin formatPlugin,
                                List<SchemaPath> projectedColumns, FragmentContext context) {
    buffer = context.getManagedBuffer();
    final Path tablePath = new Path(Preconditions.checkNotNull(subScanSpec,
      "MapRDB reader needs a sub-scan spec").getTableName());
    this.subScanSpec = subScanSpec;
    this.formatPlugin = formatPlugin;
    final IndexDesc indexDesc = subScanSpec.getIndexDesc();
    byte[] serializedFilter = subScanSpec.getSerializedFilter();
    condition = null;

    if (serializedFilter != null) {
      condition = com.mapr.db.impl.ConditionImpl.parseFrom(ByteBufs.wrap(serializedFilter));
    }

    disableCountOptimization = formatPlugin.getConfig().disableCountOptimization();
    // Below call will set the scannedFields and includeId correctly
    setColumns(projectedColumns);
    unionEnabled = context.getOptions().getOption(ExecConstants.ENABLE_UNION_TYPE);
    readNumbersAsDouble = formatPlugin.getConfig().isReadAllNumbersAsDouble();
    allTextMode = formatPlugin.getConfig().isAllTextMode();
    ignoreSchemaChange = formatPlugin.getConfig().isIgnoreSchemaChange();
    disablePushdown = !formatPlugin.getConfig().isEnablePushdown();
    nonExistentColumnsProjection = formatPlugin.getConfig().isNonExistentFieldSupport();

    // Do not use cached table handle for two reasons.
    // cached table handles default timeout is 60 min after which those handles will become stale.
    // Since execution can run for longer than 60 min, we want to get a new table handle and use it
    // instead of the one from cache.
    // Since we are setting some table options, we do not want to use shared handles.
    //
    // Call it here instead of setup since this will make sure it's called under correct UGI block when impersonation
    // is enabled and table is used with and without views.
    table = (indexDesc == null ? MapRDBImpl.getTable(tablePath) : MapRDBImpl.getIndexTable(indexDesc));

    if (condition != null) {
      logger.debug("Created record reader with query condition {}", condition.toString());
    } else {
      logger.debug("Created record reader with query condition NULL");
    }
  }

  @Override
  protected Collection<SchemaPath> transformColumns(Collection<SchemaPath> columns) {
    Set<SchemaPath> transformed = Sets.newLinkedHashSet();
    Set<SchemaPath> encodedSchemaPathSet = Sets.newLinkedHashSet();

    if (disablePushdown) {
      transformed.add(SchemaPath.STAR_COLUMN);
      includeId = true;
    } else {
      if (isStarQuery()) {
        transformed.add(SchemaPath.STAR_COLUMN);
        includeId = true;
        if (isSkipQuery() && !disableCountOptimization) {
          // `SELECT COUNT(*)` query
          idOnly = true;
          scannedFields = ID_ONLY_PROJECTION;
        }
      } else {
        Set<FieldPath> scannedFieldsSet = Sets.newTreeSet();
        Set<FieldPath> projectedFieldsSet = null;

        for (SchemaPath column : columns) {
          if (EncodedSchemaPathSet.isEncodedSchemaPath(column)) {
            encodedSchemaPathSet.add(column);
          } else {
            transformed.add(column);
            if (!DOCUMENT_SCHEMA_PATH.equals(column)) {
              FieldPath fp = getFieldPathForProjection(column);
              scannedFieldsSet.add(fp);
            } else {
              projectWholeDocument = true;
            }
          }
        }
        if (projectWholeDocument) {
          // we do not want to project the fields from the encoded field path list
          // hence make a copy of the scannedFieldsSet here for projection.
          projectedFieldsSet = new ImmutableSet.Builder<FieldPath>()
              .addAll(scannedFieldsSet).build();
        }

        if (encodedSchemaPathSet.size() > 0) {
          Collection<SchemaPath> decodedSchemaPaths = EncodedSchemaPathSet.decode(encodedSchemaPathSet);
          // now we look at the fields which are part of encoded field set and either
          // add them to scanned set or clear the scanned set if all fields were requested.
          for (SchemaPath column : decodedSchemaPaths) {
            if (column.equals(SchemaPath.STAR_COLUMN)) {
              includeId = true;
              scannedFieldsSet.clear();
              break;
            }
            scannedFieldsSet.add(getFieldPathForProjection(column));
          }
        }

        if (scannedFieldsSet.size() > 0) {
          if (includesIdField(scannedFieldsSet)) {
            includeId = true;
          }
          scannedFields = scannedFieldsSet.toArray(new FieldPath[scannedFieldsSet.size()]);
        }

        if (disableCountOptimization) {
          idOnly = (scannedFields == null);
        }

        if (projectWholeDocument) {
          projector = new FieldProjector(projectedFieldsSet);
        }

      }
    }
    return transformed;
  }

  protected FieldPath[] getScannedFields() {
    return scannedFields;
  }

  protected boolean getIdOnly() {
    return idOnly;
  }

  protected Table getTable() {
    return table;
  }

  protected boolean getIgnoreSchemaChange() {
    return ignoreSchemaChange;
  }

  @Override
  public void setup(OperatorContext context, OutputMutator output) throws ExecutionSetupException {
    this.vectorWriter = new VectorContainerWriter(output, unionEnabled);
    this.operatorContext = context;

    try {
      table.setOption(TableOption.EXCLUDEID, !includeId);
      documentStream = table.find(condition, scannedFields);
      documentReaderIterators = documentStream.documentReaders().iterator();

      if (allTextMode) {
        valueWriter = new AllTextValueWriter(buffer);
      } else if (readNumbersAsDouble) {
        valueWriter = new NumbersAsDoubleValueWriter(buffer);
      } else {
        valueWriter = new OjaiValueWriter(buffer);
      }

      if (projectWholeDocument) {
        documentWriter = new ProjectionPassthroughVectorWriter(valueWriter, projector, includeId);
      } else if (isSkipQuery()) {
        documentWriter = new RowCountVectorWriter(valueWriter);
      } else if (idOnly) {
        documentWriter = new IdOnlyVectorWriter(valueWriter);
      } else {
        documentWriter = new FieldTransferVectorWriter(valueWriter);
      }
    } catch (DBException ex) {
      throw new ExecutionSetupException(ex);
    }
  }

  @Override
  public int next() {
    Stopwatch watch = Stopwatch.createUnstarted();
    watch.start();

    vectorWriter.allocate();
    vectorWriter.reset();

    int recordCount = 0;
    reader = null;

    int maxRecordsForThisBatch = this.maxRecordsToRead >= 0?
        Math.min(BaseValueVector.INITIAL_VALUE_ALLOCATION, this.maxRecordsToRead) : BaseValueVector.INITIAL_VALUE_ALLOCATION;

    while(recordCount < maxRecordsForThisBatch) {
      vectorWriter.setPosition(recordCount);
      try {
        reader = nextDocumentReader();
        if (reader == null) {
          break; // no more documents for this reader
        } else {
          documentWriter.writeDBDocument(vectorWriter, reader);
        }
        recordCount++;
      } catch (UserException e) {
        throw UserException.unsupportedError(e)
            .addContext(String.format("Table: %s, document id: '%s'",
                table.getPath(),
                reader == null ? null : IdCodec.asString(reader.getId())))
            .build(logger);
      } catch (SchemaChangeException e) {
        String err_row = reader.getId().asJsonString();
        if (ignoreSchemaChange) {
          logger.warn("{}. Dropping row '{}' from result.", e.getMessage(), err_row);
          logger.debug("Stack trace:", e);
        } else {
          throw dataReadError(logger, e, "SchemaChangeException for row '%s'.", err_row);
        }
      }
    }

    if (nonExistentColumnsProjection && recordCount > 0) {
      JsonReaderUtils.ensureAtLeastOneField(vectorWriter, getColumns(), allTextMode, Collections.EMPTY_LIST);
    }
    vectorWriter.setValueCount(recordCount);
    if (maxRecordsToRead > 0) {
      maxRecordsToRead -= recordCount;
    }
    logger.debug("Took {} ms to get {} records", watch.elapsed(TimeUnit.MILLISECONDS), recordCount);
    return recordCount;
  }

  protected DBDocumentReaderBase nextDocumentReader() {
    final OperatorStats operatorStats = operatorContext == null ? null : operatorContext.getStats();
    try {
      if (operatorStats != null) {
        operatorStats.startWait();
      }
      try {
        if (!documentReaderIterators.hasNext()) {
          return null;
        } else {
          return (DBDocumentReaderBase) documentReaderIterators.next();
        }
      } finally {
        if (operatorStats != null) {
          operatorStats.stopWait();
        }
      }
    } catch (DBException e) {
      throw dataReadError(logger, e);
    }
  }

  /*
   * Extracts contiguous named segments from the SchemaPath, starting from the
   * root segment and build the FieldPath from it for projection.
   *
   * This is due to bug 22726 and 22727, which cause DB's DocumentReaders to
   * behave incorrectly for sparse lists, hence we avoid projecting beyond the
   * first encountered ARRAY field and let Drill handle the projection.
   */
  private static FieldPath getFieldPathForProjection(SchemaPath column) {
    Stack<PathSegment.NameSegment> pathSegments = new Stack<>();
    PathSegment seg = column.getRootSegment();
    while (seg != null && seg.isNamed()) {
      pathSegments.push((PathSegment.NameSegment) seg);
      seg = seg.getChild();
    }
    FieldSegment.NameSegment child = null;
    while (!pathSegments.isEmpty()) {
      child = new FieldSegment.NameSegment(pathSegments.pop().getPath(), child, false);
    }
    return new FieldPath(child);
  }

  public static boolean includesIdField(Collection<FieldPath> projected) {
    return Iterables.tryFind(projected, new Predicate<FieldPath>() {
      @Override
      public boolean apply(FieldPath path) {
        return Preconditions.checkNotNull(path).equals(ID_FIELD);
      }
    }).isPresent();
  }

  @Override
  public void close() {
    if (documentStream != null) {
      documentStream.close();
    }
    if (table != null) {
      table.close();
    }
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder("MaprDBJsonRecordReader[Table=")
        .append(table != null ? table.getPath() : null);
    if (reader != null) {
      sb.append(", Document ID=")
          .append(IdCodec.asString(reader.getId()));
    }
    sb.append(", reader=")
        .append(reader)
        .append(']');
    return sb.toString();
  }
}
