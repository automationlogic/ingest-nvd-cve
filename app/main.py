from flask import Flask

import requests as rq
import logging
import os
import time
import datetime
import csv
from random import randint

from ijson import parse, items
import json
import zipfile
from io import BytesIO
from urllib import request
import decimal 

from google.cloud import pubsub_v1
from google.cloud import bigquery
from google.cloud.exceptions import NotFound, Conflict

# pylint: disable=E1101

#JSONDecoder doesnt accept Decimal objects => subclassing json.JSONEncoder
#allows decimals as part of an object to be encoded as a json string
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)

app = Flask(__name__)

@app.route('/')
def ok():
    return 'ok'

@app.route('/ingest')
def ingest():
    topic_name = os.getenv('TOPIC')
    url = os.getenv('URL')

    publisher = pubsub_v1.PublisherClient(batch_settings=pubsub_v1.types.BatchSettings(max_latency=5))
    topic_path = publisher.topic_path(project_id, topic_name)

    request = rq.get(url)
    zip_file = zipfile.ZipFile(BytesIO(request.content))

    # unzips zipfile
    zipfilee = zip_file.open('nvdcve-1.1-2019.json')

    # zipfile is passed into ijson.items method which creates a generator, CVE_Items
    # creates json object for each row to be uploaded to BigQuery
    lines = items(zipfilee, "CVE_Items.item")

    chunk_size = 50

    print('Publishing data to {} ...'.format(topic_path))
    count = 0
    chunk = []
    for line in lines:
        json_record=json.dumps(line, cls=DecimalEncoder)
        if len(json_record) > 0:
            if count < chunk_size:
                chunk.append(json_record)
                count += 1
            if count == chunk_size:
                bytes_chunk = bytes("\r\n".join(chunk).encode('utf-8'))
                publisher.publish(topic_path, data=bytes_chunk)
                chunk = []
                count = 0
    if count > 0:
        bytes_chunk = bytes("\r\n".join(chunk).encode('utf-8'))
        publisher.publish(topic_path, data=bytes_chunk)

    subscribe()

    return 'ok'

def subscribe():
    future = subscriber.subscribe(subscription_path, callback=callback)

    # The subscriber is non-blocking, so we must keep the main thread from
    # exiting to allow it to process messages in the background.
    print('Listening for messages on {} ...'.format(subscription_path))
    loop = True
    while loop:
        response = subscriber.pull(subscription_path, 10)
        if len(response.received_messages) > 0:
            time.sleep(1)
        else:
            print('No more messages, canceling subscription...')

            future.cancel()
            loop = False
            return

def callback(message):
    if message.data:
        decoded_message = message.data.decode('utf-8')
        lines = decoded_message.splitlines()
        for line in lines: 
            line = json.loads(line)
            rows_to_insert = []
            rows_to_insert.append(line)
            try:
                table = bq_client.get_table(table_ref)
            except NotFound:
                create_table()
                table = bq_client.get_table(table_ref)

            print("Inserting {} rows into BigQuery ...".format(len(rows_to_insert)))
            errors = bq_client.insert_rows_json(table, rows_to_insert)
            if errors != []:
                print(errors)
            else:
                message.ack()
    assert errors == []

def create_table():
    schema = [
            bigquery.SchemaField("lastModifiedDate", 'TIMESTAMP'),
            bigquery.SchemaField("publishedDate", 'TIMESTAMP'),
            bigquery.SchemaField("impact", 'RECORD',
                    fields=(
                        bigquery.SchemaField("baseMetricV3", 'RECORD',
                            fields=(
                                bigquery.SchemaField("impactScore", 'FLOAT'),
                                bigquery.SchemaField("exploitabilityScore", 'FLOAT'),
                                bigquery.SchemaField("cvssV3", 'RECORD',
                                    fields=(
                                        bigquery.SchemaField("baseSeverity", 'STRING'),
                                        bigquery.SchemaField("baseScore", 'FLOAT'),
                                        bigquery.SchemaField("version", 'FLOAT'),
                                        bigquery.SchemaField("confidentialityImpact", 'STRING'),
                                        bigquery.SchemaField("scope", 'STRING'),
                                        bigquery.SchemaField("availabilityImpact", 'STRING'),
                                        bigquery.SchemaField("attackVector", 'STRING'),
                                        bigquery.SchemaField("integrityImpact", 'STRING'),
                                        bigquery.SchemaField("attackComplexity", 'STRING'),
                                        bigquery.SchemaField("vectorString", 'STRING'),
                                        bigquery.SchemaField("userInteraction", 'STRING'),
                                        bigquery.SchemaField("privilegesRequired", 'STRING'),
                                    )
                                ),
                            )
                        ),
                        bigquery.SchemaField("baseMetricV2", 'RECORD',
                            fields=(
                                bigquery.SchemaField("acInsufInfo", 'BOOLEAN'),
                                bigquery.SchemaField("obtainAllPrivilege", 'BOOLEAN'),
                                bigquery.SchemaField("userInteractionRequired", 'BOOLEAN'),
                                bigquery.SchemaField("obtainOtherPrivilege", 'BOOLEAN'),
                                bigquery.SchemaField("impactScore", 'FLOAT'),
                                bigquery.SchemaField("obtainUserPrivilege", 'BOOLEAN'),
                                bigquery.SchemaField("exploitabilityScore", 'FLOAT'),
                                bigquery.SchemaField("severity", 'STRING'),
                                bigquery.SchemaField("cvssV2", 'RECORD',
                                    fields=(
                                        bigquery.SchemaField("baseScore", 'FLOAT'),
                                        bigquery.SchemaField("integrityImpact", 'STRING'),
                                        bigquery.SchemaField("authentication", 'STRING'),
                                        bigquery.SchemaField("accessComplexity", 'STRING'),
                                        bigquery.SchemaField("accessVector", 'STRING'),
                                        bigquery.SchemaField("availabilityImpact", 'STRING'),
                                        bigquery.SchemaField("vectorString", 'STRING'),
                                        bigquery.SchemaField("confidentialityImpact", 'STRING'),
                                        bigquery.SchemaField("version", 'FLOAT'),
                                    )
                                ),
                            )
                        ),
                    )
            ),
            bigquery.SchemaField("configurations", 'RECORD',
                    fields=(
                        bigquery.SchemaField("nodes", 'RECORD', mode="REPEATED",
                            fields=(
                                bigquery.SchemaField("children", 'RECORD', mode="REPEATED",
                                    fields=(
                                        bigquery.SchemaField("cpe_match", 'RECORD', mode="REPEATED",
                                            fields=(
                                                bigquery.SchemaField("versionEndIncluding", 'STRING'),
                                                bigquery.SchemaField("cpe23Uri", 'STRING'),
                                                bigquery.SchemaField("vulnerable", 'BOOLEAN'),
                                            )
                                        ),
                                        bigquery.SchemaField("operator", 'STRING'),
                                    )
                                ),
                                bigquery.SchemaField("cpe_match", 'RECORD', mode="REPEATED",
                                    fields=(
                                        bigquery.SchemaField("versionStartIncluding", 'STRING'),
                                        bigquery.SchemaField("versionEndExcluding", 'STRING'),
                                        bigquery.SchemaField("versionEndIncluding", 'STRING'),
                                        bigquery.SchemaField("cpe23Uri", 'STRING'),
                                        bigquery.SchemaField("vulnerable", 'BOOLEAN'),
                                    )
                                ),
                                bigquery.SchemaField("operator", 'STRING'),
                            )
                        ),
                        bigquery.SchemaField("CVE_data_version", 'FLOAT'),
                    )
            ),
            bigquery.SchemaField("cve", 'RECORD',
                    fields=(
                        bigquery.SchemaField("description", 'RECORD',
                            fields=(
                                bigquery.SchemaField("description_data", 'RECORD', mode="REPEATED",
                                    fields=(
                                        bigquery.SchemaField("value", 'STRING'),
                                        bigquery.SchemaField("lang", 'STRING'),
                                    )
                                ),
                            )
                        ),
                        bigquery.SchemaField("references", 'RECORD',
                            fields=(
                                bigquery.SchemaField("reference_data", 'RECORD', mode="REPEATED",
                                    fields=(
                                        bigquery.SchemaField("tags", 'STRING', mode="REPEATED"),
                                        bigquery.SchemaField("refsource", 'STRING'),
                                        bigquery.SchemaField("name", 'STRING'),
                                        bigquery.SchemaField("url", 'STRING'),
                                    )
                                ),
                            )
                        ),
                        bigquery.SchemaField("problemtype", 'RECORD',
                            fields=(
                                bigquery.SchemaField("problemtype_data", 'RECORD', mode="REPEATED",
                                    fields=(
                                        bigquery.SchemaField("description", 'RECORD', mode="REPEATED",
                                            fields=(
                                                bigquery.SchemaField("value", 'STRING'),
                                                bigquery.SchemaField("lang", 'STRING'),
                                            )
                                        ),
                                    )
                                ),
                            )
                        ),
                        bigquery.SchemaField("CVE_data_meta", 'RECORD',
                            fields=(
                                bigquery.SchemaField("ASSIGNER", 'STRING'),
                                bigquery.SchemaField("ID", 'STRING'),
                            )
                        ),
                        bigquery.SchemaField("data_version", 'FLOAT'),
                        bigquery.SchemaField("data_format", 'STRING'),
                        bigquery.SchemaField("affects", 'RECORD',
                            fields=(
                                bigquery.SchemaField("vendor", 'RECORD',
                                    fields=(
                                        bigquery.SchemaField("vendor_data", 'RECORD', mode="REPEATED",
                                            fields=(
                                                bigquery.SchemaField("product", 'RECORD',
                                                    fields=(
                                                        bigquery.SchemaField("product_data", 'RECORD', mode="REPEATED",
                                                            fields=(
                                                                bigquery.SchemaField("version", 'RECORD',
                                                                    fields=(
                                                                        bigquery.SchemaField("version_data", 'RECORD', mode="REPEATED",
                                                                            fields=(
                                                                                bigquery.SchemaField("version_affected", 'STRING'),
                                                                                bigquery.SchemaField("version_value", 'STRING'),
                                                                            )
                                                                        ),
                                                                    )
                                                                ),
                                                                bigquery.SchemaField("product_name", 'STRING'),
                                                            )
                                                        ),
                                                    )
                                                ),
                                                bigquery.SchemaField("vendor_name", 'STRING'),
                                            )
                                        ),
                                    )
                                ),
                            )
                        ),
                        bigquery.SchemaField("data_type", 'STRING'),
                    )
            ),
]


    table = bigquery.Table(table_ref, schema=schema)
    try:
        bq_client.get_table(table)
    except NotFound:
        try:
            table = bq_client.create_table(table)
            print("Created table {}.{}.{}".format(table.project, table.dataset_id, table.table_id))
            print("Going to sleep for 90 seconds to ensure data availability in newly created table")
            time.sleep(90)
        except Conflict:
            pass

    return

@app.errorhandler(500)
def server_error(e):
    print('An internal error occurred')
    return 'An internal error occurred.', 500

print("Preparing..")
project_id = os.getenv('PROJECT')
subscription_name = os.getenv('SUBSCRIPTION')

subscriber = pubsub_v1.SubscriberClient()
subscription_path = subscriber.subscription_path(project_id, subscription_name)

dataset_id = os.getenv('DATASET')
table_id = os.getenv('TABLE')

bq_client = bigquery.Client()
table_ref = bq_client.dataset(dataset_id).table(table_id)
