/*
 * Copyright 2018 LinkedIn Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package azkaban;

import java.time.Duration;

/**
 * Constants used in configuration files or shared among classes.
 *
 * <p>Conventions:
 *
 * <p>Internal constants to be put in the {@link Constants} class
 *
 * <p>Configuration keys to be put in the {@link ConfigurationKeys} class
 *
 * <p>Flow level properties keys to be put in the {@link FlowProperties} class
 *
 * <p>Job level Properties keys to be put in the {@link JobProperties} class
 *
 * <p>Use '.' to separate name spaces and '_" to separate words in the same namespace. e.g.
 * azkaban.job.some_key</p>
 */
public class Constants {

  // Azkaban Flow Versions
  public static final double DEFAULT_AZKABAN_FLOW_VERSION = 1.0;
  public static final double AZKABAN_FLOW_VERSION_2_0 = 2.0;

  // Flow 2.0 file suffix
  public static final String PROJECT_FILE_SUFFIX = ".project";
  public static final String FLOW_FILE_SUFFIX = ".flow";

  // Flow 2.0 node type
  public static final String NODE_TYPE = "type";
  public static final String FLOW_NODE_TYPE = "flow";

  // Flow 2.0 flow and job path delimiter
  public static final String PATH_DELIMITER = ":";

  // Job properties override suffix
  public static final String JOB_OVERRIDE_SUFFIX = ".jor";

  // Names and paths of various file names to configure Azkaban
  public static final String AZKABAN_PROPERTIES_FILE = "azkaban.properties";
  public static final String AZKABAN_PRIVATE_PROPERTIES_FILE = "azkaban.private.properties";
  public static final String DEFAULT_CONF_PATH = "conf";
  public static final String DEFAULT_EXECUTOR_PORT_FILE = "executor.port";

  public static final String AZKABAN_SERVLET_CONTEXT_KEY = "azkaban_app";

  // Internal username used to perform SLA action
  public static final String AZKABAN_SLA_CHECKER_USERNAME = "azkaban_sla";

  // Memory check retry interval when OOM in ms
  public static final long MEMORY_CHECK_INTERVAL_MS = 1000 * 60 * 1;

  // Max number of memory check retry
  public static final int MEMORY_CHECK_RETRY_LIMIT = 720;
  public static final int DEFAULT_PORT_NUMBER = 8081;
  public static final int DEFAULT_SSL_PORT_NUMBER = 8443;
  public static final int DEFAULT_JETTY_MAX_THREAD_COUNT = 20;

  // One Schedule's default End Time: 01/01/2050, 00:00:00, UTC
  public static final long DEFAULT_SCHEDULE_END_EPOCH_TIME = 2524608000000L;

  // Default flow trigger max wait time
  public static final Duration DEFAULT_FLOW_TRIGGER_MAX_WAIT_TIME = Duration.ofDays(10);

  public static final Duration MIN_FLOW_TRIGGER_WAIT_TIME = Duration.ofMinutes(1);

  // The flow exec id for a flow trigger instance which hasn't started a flow yet
  public static final int UNASSIGNED_EXEC_ID = -1;

  // The flow exec id for a flow trigger instance unable to trigger a flow yet
  public static final int FAILED_EXEC_ID = -2;

  // Default locked flow error message
  public static final String DEFAULT_LOCKED_FLOW_ERROR_MESSAGE =
      "Flow %s in project %s is locked. This is either a repeatedly failing flow, or an ineffcient"
          + " flow. Please refer to the Dr. Elephant report for this flow for more information.";

  // Default maximum number of concurrent runs for a single flow
  public static final int DEFAULT_MAX_ONCURRENT_RUNS_ONEFLOW = 30;

  // How often executors will poll new executions in Poll Dispatch model
  public static final int DEFAULT_AZKABAN_POLLING_INTERVAL_MS = 1000;

  // Executors can use cpu load calculated from this period to take/skip polling turns
  public static final int DEFAULT_AZKABAN_POLLING_CRITERIA_CPU_LOAD_PERIOD_SEC = 60;

  public static class ConfigurationKeys {

    // Configures Azkaban to use new polling model for dispatching
    public static final String AZKABAN_POLL_MODEL = "azkaban.poll.model";
    public static final String AZKABAN_POLLING_INTERVAL_MS = "azkaban.polling.interval.ms";
    public static final String AZKABAN_POLLING_CRITERIA_FLOW_THREADS_AVAILABLE =
        "azkaban.polling_criteria.flow_threads_available";
    public static final String AZKABAN_POLLING_CRITERIA_MIN_FREE_MEMORY_GB =
        "azkaban.polling_criteria.min_free_memory_gb";
    public static final String AZKABAN_POLLING_CRITERIA_MAX_CPU_UTILIZATION_PCT =
        "azkaban.polling_criteria.max_cpu_utilization_pct";
    public static final String AZKABAN_POLLING_CRITERIA_CPU_LOAD_PERIOD_SEC =
        "azkaban.polling_criteria.cpu_load_period_sec";

    // Configures properties for Azkaban executor health check
    public static final String AZKABAN_EXECUTOR_HEALTHCHECK_INTERVAL_MIN = "azkaban.executor.healthcheck.interval.min";
    public static final String AZKABAN_EXECUTOR_MAX_FAILURE_COUNT = "azkaban.executor.max.failurecount";
    public static final String AZKABAN_ADMIN_ALERT_EMAIL = "azkaban.admin.alert.email";

    // Configures Azkaban Flow Version in project YAML file
    public static final String AZKABAN_FLOW_VERSION = "azkaban-flow-version";

    // These properties are configurable through azkaban.properties
    public static final String AZKABAN_PID_FILENAME = "azkaban.pid.filename";

    // Defines a list of external links, each referred to as a topic
    public static final String AZKABAN_SERVER_EXTERNAL_TOPICS = "azkaban.server.external.topics";

    // External URL template of a given topic, specified in the list defined above
    public static final String AZKABAN_SERVER_EXTERNAL_TOPIC_URL = "azkaban.server.external.${topic}.url";

    // Designates one of the external link topics to correspond to an execution analyzer
    public static final String AZKABAN_SERVER_EXTERNAL_ANALYZER_TOPIC = "azkaban.server.external.analyzer.topic";
    public static final String AZKABAN_SERVER_EXTERNAL_ANALYZER_LABEL = "azkaban.server.external.analyzer.label";

    // Designates one of the external link topics to correspond to a job log viewer
    public static final String AZKABAN_SERVER_EXTERNAL_LOGVIEWER_TOPIC = "azkaban.server.external.logviewer.topic";
    public static final String AZKABAN_SERVER_EXTERNAL_LOGVIEWER_LABEL = "azkaban.server.external.logviewer.label";

    /*
     * Hadoop/Spark user job link.
     * Example:
     * a) azkaban.server.external.resource_manager_job_url=http://***rm***:8088/cluster/app/application_${application.id}
     * b) azkaban.server.external.history_server_job_url=http://***jh***:19888/jobhistory/job/job_${application.id}
     * c) azkaban.server.external.spark_history_server_job_url=http://***sh***:18080/history/application_${application.id}/1/jobs
     * */
    public static final String RESOURCE_MANAGER_JOB_URL = "azkaban.server.external.resource_manager_job_url";
    public static final String HISTORY_SERVER_JOB_URL = "azkaban.server.external.history_server_job_url";
    public static final String SPARK_HISTORY_SERVER_JOB_URL = "azkaban.server.external.spark_history_server_job_url";

    // Configures the Kafka appender for logging user jobs, specified for the exec server
    public static final String AZKABAN_SERVER_LOGGING_KAFKA_BROKERLIST = "azkaban.server.logging.kafka.brokerList";
    public static final String AZKABAN_SERVER_LOGGING_KAFKA_TOPIC = "azkaban.server.logging.kafka.topic";

    // Represent the class name of azkaban metrics reporter.
    public static final String CUSTOM_METRICS_REPORTER_CLASS_NAME = "azkaban.metrics.reporter.name";

    // Represent the metrics server URL.
    public static final String METRICS_SERVER_URL = "azkaban.metrics.server.url";

    public static final String IS_METRICS_ENABLED = "azkaban.is.metrics.enabled";

    // User facing web server configurations used to construct the user facing server URLs. They are useful when there is a reverse proxy between Azkaban web servers and users.
    // enduser -> myazkabanhost:443 -> proxy -> localhost:8081
    // when this parameters set then these parameters are used to generate email links.
    // if these parameters are not set then jetty.hostname, and jetty.port(if ssl configured jetty.ssl.port) are used.
    public static final String AZKABAN_WEBSERVER_EXTERNAL_HOSTNAME = "azkaban.webserver.external_hostname";
    public static final String AZKABAN_WEBSERVER_EXTERNAL_SSL_PORT = "azkaban.webserver.external_ssl_port";
    public static final String AZKABAN_WEBSERVER_EXTERNAL_PORT = "azkaban.webserver.external_port";

    // Hostname for the host, if not specified, canonical hostname will be used
    public static final String AZKABAN_SERVER_HOST_NAME = "azkaban.server.hostname";

    // List of users we prevent azkaban from running flows as. (ie: root, azkaban)
    public static final String BLACK_LISTED_USERS = "azkaban.server.blacklist.users";

    // Path name of execute-as-user executable
    public static final String AZKABAN_SERVER_NATIVE_LIB_FOLDER = "azkaban.native.lib";

    // Name of *nix group associated with the process running Azkaban
    public static final String AZKABAN_SERVER_GROUP_NAME = "azkaban.group.name";

    // Legacy configs section, new configs should follow the naming convention of azkaban.server.<rest of the name> for server configs.

    public static final String EXECUTOR_PORT_FILE = "executor.portfile";
    // To set a fixed port for executor-server. Otherwise some available port is used.
    public static final String EXECUTOR_PORT = "executor.port";

    // Max flow running time in mins, server will kill flows running longer than this setting.
    // if not set or <= 0, then there's no restriction on running time.
    public static final String AZKABAN_MAX_FLOW_RUNNING_MINS = "azkaban.server.flow.max.running.minutes";

    public static final String AZKABAN_STORAGE_TYPE = "azkaban.storage.type";
    public static final String AZKABAN_STORAGE_LOCAL_BASEDIR = "azkaban.storage.local.basedir";
    public static final String HADOOP_CONF_DIR_PATH = "hadoop.conf.dir.path";
    public static final String AZKABAN_STORAGE_HDFS_ROOT_URI = "azkaban.storage.hdfs.root.uri";
    public static final String AZKABAN_KERBEROS_PRINCIPAL = "azkaban.kerberos.principal";
    public static final String AZKABAN_KEYTAB_PATH = "azkaban.keytab.path";
    public static final String PROJECT_TEMP_DIR = "project.temp.dir";

    // Event reporting properties
    public static final String AZKABAN_EVENT_REPORTING_CLASS_PARAM =
        "azkaban.event.reporting.class";
    public static final String AZKABAN_EVENT_REPORTING_ENABLED = "azkaban.event.reporting.enabled";
    // Comma separated list of properties to propagate from flow to Event reporter metadata
    public static final String AZKABAN_EVENT_REPORTING_PROPERTIES_TO_PROPAGATE = "azkaban.event.reporting.propagateProperties";
    public static final String AZKABAN_EVENT_REPORTING_KAFKA_BROKERS =
        "azkaban.event.reporting.kafka.brokers";
    public static final String AZKABAN_EVENT_REPORTING_KAFKA_TOPIC =
        "azkaban.event.reporting.kafka.topic";
    public static final String AZKABAN_EVENT_REPORTING_KAFKA_SCHEMA_REGISTRY_URL =
        "azkaban.event.reporting.kafka.schema.registry.url";

    /*
     * The max number of artifacts retained per project.
     * Accepted Values:
     * - 0 : Save all artifacts. No clean up is done on storage.
     * - 1, 2, 3, ... (any +ve integer 'n') : Maintain 'n' latest versions in storage
     *
     * Note: Having an unacceptable value results in an exception and the service would REFUSE
     * to start.
     *
     * Example:
     * a) azkaban.storage.artifact.max.retention=all
     *    implies save all artifacts
     * b) azkaban.storage.artifact.max.retention=3
     *    implies save latest 3 versions saved in storage.
     **/
    public static final String AZKABAN_STORAGE_ARTIFACT_MAX_RETENTION = "azkaban.storage.artifact.max.retention";

    // enable quartz scheduler and flow trigger if true.
    public static final String ENABLE_QUARTZ = "azkaban.server.schedule.enable_quartz";

    public static final String CUSTOM_CREDENTIAL_NAME = "azkaban.security.credential";

    // dir to keep dependency plugins
    public static final String DEPENDENCY_PLUGIN_DIR = "azkaban.dependency.plugin.dir";

    public static final String USE_MULTIPLE_EXECUTORS = "azkaban.use.multiple.executors";
    public static final String MAX_CONCURRENT_RUNS_ONEFLOW = "azkaban.max.concurrent.runs.oneflow";

    // list of whitelisted flows, with specific max number of concurrent runs. Format:
    // <project 1>,<flow 1>,<number>;<project 2>,<flow 2>,<number>
    public static final String CONCURRENT_RUNS_ONEFLOW_WHITELIST =
        "azkaban.concurrent.runs.oneflow.whitelist";

    public static final String WEBSERVER_QUEUE_SIZE = "azkaban.webserver.queue.size";
    public static final String ACTIVE_EXECUTOR_REFRESH_IN_MS =
        "azkaban.activeexecutor.refresh.milisecinterval";
    public static final String ACTIVE_EXECUTOR_REFRESH_IN_NUM_FLOW =
        "azkaban.activeexecutor.refresh.flowinterval";
    public static final String EXECUTORINFO_REFRESH_MAX_THREADS =
        "azkaban.executorinfo.refresh.maxThreads";
    public static final String MAX_DISPATCHING_ERRORS_PERMITTED = "azkaban.maxDispatchingErrors";
    public static final String EXECUTOR_SELECTOR_FILTERS = "azkaban.executorselector.filters";
    public static final String EXECUTOR_SELECTOR_COMPARATOR_PREFIX =
        "azkaban.executorselector.comparator.";
    public static final String QUEUEPROCESSING_ENABLED = "azkaban.queueprocessing.enabled";

    public static final String SESSION_TIME_TO_LIVE = "session.time.to.live";

    // allowed max number of sessions per user per IP
    public static final String MAX_SESSION_NUMBER_PER_IP_PER_USER = "azkaban.session"
        + ".max_number_per_ip_per_user";

    // allowed max size of shared project dir (percentage of partition size), e.g 0.8
    public static final String PROJECT_CACHE_SIZE_PERCENTAGE = "azkaban"
        + ".project_cache_size_percentage_of_disk";

    // how many older versions of project files are kept in DB before deleting them
    public static final String PROJECT_VERSION_RETENTION = "project.version.retention";

    // number of rows to be displayed on the executions page.
    public static final String DISPLAY_EXECUTION_PAGE_SIZE = "azkaban.display.execution_page_size";

    // locked flow error message. Parameters passed in are the flow name and project name.
    public static final String AZKABAN_LOCKED_FLOW_ERROR_MESSAGE =
        "azkaban.locked.flow.error.message";

    // AAD Related contents

    // class to use to provide AADCredentials for a user. (Should be instance AADCredentialsRetriever)
    public static final String AZKABAN_AAD_CREDENTIAL_RETRIEVER_NAME = "azkaban.aad.credentialretriever.class";

    public static final String AZKABAN_AAD_KEY_FOR_CREDS = "azkaban.aad.provider.key";
    public static final String AZAKABN_AAD_KEY_FOR_CREDS_DEFAULT = "aadAccessToken";

    // authority, clientID and secret used to authenticate to AzureAD
    public static final String AZKABAN_AAD_AUTHORITY = "azkaban.aad.authority";
    public static final String AZKABAN_AAD_CLIENT_ID = "azkaban.aad.client_id";
    public static final String AZKABAN_AAD_CLIENT_SECRET = "azkaban.aad.client_secret";


  }

  public static class FlowProperties {

    // Basic properties of flows as set by the executor server
    public static final String AZKABAN_FLOW_PROJECT_NAME = "azkaban.flow.projectname";
    public static final String AZKABAN_FLOW_FLOW_ID = "azkaban.flow.flowid";
    public static final String AZKABAN_FLOW_SUBMIT_USER = "azkaban.flow.submituser";
    public static final String AZKABAN_FLOW_EXEC_ID = "azkaban.flow.execid";
    public static final String AZKABAN_FLOW_PROJECT_VERSION = "azkaban.flow.projectversion";
  }

  public static class JobProperties {

    // Job property that enables/disables using Kafka logging of user job logs
    public static final String AZKABAN_JOB_LOGGING_KAFKA_ENABLE = "azkaban.job.logging.kafka.enable";

    /*
     * this parameter is used to replace EXTRA_HCAT_LOCATION that could fail when one of the uris is not available.
     * EXTRA_HCAT_CLUSTERS has the following format:
     * other_hcat_clusters = "thrift://hcat1:port,thrift://hcat2:port;thrift://hcat3:port,thrift://hcat4:port"
     * Each string in the parenthesis is regarded as a "cluster", and we will get a delegation token from each cluster.
     * The uris(hcat servers) in a "cluster" ensures HA is provided.
     **/
    public static final String EXTRA_HCAT_CLUSTERS = "azkaban.job.hive.other_hcat_clusters";

    /*
     * the settings to be defined by user indicating if there are hcat locations other than the
     * default one the system should pre-fetch hcat token from. Note: Multiple thrift uris are
     * supported, use comma to separate the values, values are case insensitive.
     **/
    // Use EXTRA_HCAT_CLUSTERS instead
    @Deprecated
    public static final String EXTRA_HCAT_LOCATION = "other_hcat_location";

    // If true, AZ will fetches the jobs' certificate from remote Certificate Authority.
    public static final String ENABLE_JOB_SSL = "azkaban.job.enable.ssl";

    // Job properties that indicate maximum memory size
    public static final String JOB_MAX_XMS = "job.max.Xms";
    public static final String MAX_XMS_DEFAULT = "1G";
    public static final String JOB_MAX_XMX = "job.max.Xmx";
    public static final String MAX_XMX_DEFAULT = "2G";
    // The hadoop user the job should run under. If not specified, it will default to submit user.
    public static final String USER_TO_PROXY = "user.to.proxy";

    /**
     * Format string for Log4j's EnhancedPatternLayout
     */
    public static final String JOB_LOG_LAYOUT = "azkaban.job.log.layout";
  }

  public static class JobCallbackProperties {

    public static final String JOBCALLBACK_CONNECTION_REQUEST_TIMEOUT = "jobcallback.connection.request.timeout";
    public static final String JOBCALLBACK_CONNECTION_TIMEOUT = "jobcallback.connection.timeout";
    public static final String JOBCALLBACK_SOCKET_TIMEOUT = "jobcallback.socket.timeout";
    public static final String JOBCALLBACK_RESPONSE_WAIT_TIMEOUT = "jobcallback.response.wait.timeout";
    public static final String JOBCALLBACK_THREAD_POOL_SIZE = "jobcallback.thread.pool.size";
  }

  public static class FlowTriggerProps {

    // Flow trigger props
    public static final String SCHEDULE_TYPE = "type";
    public static final String CRON_SCHEDULE_TYPE = "cron";
    public static final String SCHEDULE_VALUE = "value";
    public static final String DEP_NAME = "name";

    // Flow trigger dependency run time props
    public static final String START_TIME = "startTime";
    public static final String TRIGGER_INSTANCE_ID = "triggerInstanceId";
  }
}
