# Ingest NVD CVE

## Overview

The ingestion process fetches the National Vulnerability Database (NVD), which is the U.S. government repository of standards based vulnerability management data represented. The NVD includes databases of security checklist references, security-related software flaws, misconfigurations, product names, and impact metrics. The NVD performs analysis on Common Vulnerability Exposures (CVEs) that have been published to the CVE Dictionary.

NVD CVE data from its [online source](https://nvd.nist.gov/vuln/data-feeds) is part of expanding the POC which originally used iris data to ingest. It runs as an App Engine app, which handles both fetching the data and placing it on a Pub/Sub topic, as well as reading it from Pub/Sub and inserting it into BigQuery.  

## Prerequisites

1. [Platform bootstrap](https://github.com/automationlogic/platform-bootstrap)
2. [Analytics infra](https://github.com/automationlogic/analytics-infra)

## Configuration

The app configuration resides in a `app.yaml` template called `app.yaml.tmpl`. The reason for the template is to allow Cloud Build to inject environment variables into the configuration file if needed.

```
URL: https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.zip
PROJECT: $ANALYTICS_PROJECT    # replace in cloud build step
TOPIC: nvd-cve
SUBSCRIPTION: nvd-cve
DATASET: nvd_cve
TABLE: nvd_cve
```

The `$ANALYTICS_PROJECT` environment variable is a pipeline substitution in the pipeline trigger. It is injected as part of a Cloud Build step:

`sed -e "s/\$$ANALYTICS_PROJECT/$_ANALYTICS_PROJECT/g" app.yaml.tmpl > app.yaml`

It is passed through from the [Platform Bootstrap](https://github.com/automationlogic/platform-bootstrap) process, which is where it is originally configured.

## Run

The pipeline is automatically triggered when code is pushed. It can also be triggered manually via the console.
