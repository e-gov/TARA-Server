package ee.ria.sso.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.HttpClientUtils;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.endpoint.AbstractEndpoint;
import org.springframework.boot.actuate.health.DataSourceHealthIndicator;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;

@Component
@ConfigurationProperties(
        prefix = "endpoints.heartbeat"
)
public class HeartbeatEndpoint extends AbstractEndpoint<Map<String, Object>> {

    public static final String RESPONSE_PARAM_STATUS = "status";
    public static final String RESPONSE_PARAM_NAME = "name";
    public static final String RESPONSE_PARAM_VERSION = "version";
    public static final String RESPONSE_PARAM_COMMIT_ID = "commitId";
    public static final String RESPONSE_PARAM_COMMIT_BRANCH = "commitBranch";
    public static final String RESPONSE_PARAM_BUILD_TIME = "buildTime";
    public static final String RESPONSE_PARAM_START_TIME = "startTime";
    public static final String RESPONSE_PARAM_CURRENT_TIME = "currentTime";
    public static final String RESPONSE_PARAM_UP_TIME = "uptime";
    public static final String RESPONSE_PARAM_DEPENDENCIES = "dependencies";
    public static final String NOT_AVAILABLE = "N/A";
    public static final String DEPENDENCY_NAME_SERVICE_REGISTRY = "JPA Service Registry";
    public static final String DEPENDENCY_NAME_EIDAS_CLIENT = "eIDAS-Client";

    private static final Logger LOGGER = LoggerFactory.getLogger(HeartbeatEndpoint.class);

    private CloseableHttpClient httpClient;
    private int timeout = 3;
    private String appName;
    private String appVersion;
    private String commitId;
    private String commitBranch;
    private Instant buildTime;
    private Instant startTime;
    private List<Dependency> dependencies;

    @Autowired
    private ApplicationContext context;

    @Value("${eidas.heartbeatUrl:}")
    private String eidasHeartbeatUrl;

    public HeartbeatEndpoint() {
        super("heartbeat", false);
    }

    @PostConstruct
    public void setUp() {
        try {
            setApplicationBuildProperties();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to initialize application build info", e);
        }
        try {
            setApplicationGitProperties();
        } catch (RuntimeException e) {
            LOGGER.error("Failed to initialize application git info", e);
        }

        startTime = getCurrentTime();

        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectTimeout(timeout * 1000)
                .setConnectionRequestTimeout(timeout * 1000)
                .setSocketTimeout(timeout * 1000)
                .build();

        httpClient = HttpClientBuilder.create()
                .disableAutomaticRetries()
                .setDefaultRequestConfig(requestConfig)
                .build();

        dependencies = new ArrayList<>(2);
        dependencies.add(createServiceRegistryDependency());
        if (StringUtils.isNotEmpty(eidasHeartbeatUrl)) {
            dependencies.add(createEidasClientDependency());
        }
    }

    @PreDestroy
    public void preDestroy() {
        HttpClientUtils.closeQuietly(httpClient);
    }

    @Override
    public Map<String, Object> invoke() {
        Map<String, Object> response = new LinkedHashMap<>();
        List<Map<String, Object>> dependencyStates = dependencies.stream()
                .map(d -> d.getCurrentState()).collect(Collectors.toList());
        Instant currentTime = getCurrentTime();

        response.put(RESPONSE_PARAM_STATUS, formatValue(
                dependencyStates.stream()
                        .map(ds -> (Status) ds.get(RESPONSE_PARAM_STATUS))
                        .min(Comparator.naturalOrder())
                        .get()
        ));

        response.put(RESPONSE_PARAM_NAME, formatValue(appName));
        response.put(RESPONSE_PARAM_VERSION, formatValue(appVersion));
        response.put(RESPONSE_PARAM_COMMIT_ID, formatValue(commitId));
        response.put(RESPONSE_PARAM_COMMIT_BRANCH, formatValue(commitBranch));
        response.put(RESPONSE_PARAM_BUILD_TIME, formatValue(formatTime(buildTime)));
        response.put(RESPONSE_PARAM_START_TIME, formatValue(formatTime(startTime)));
        response.put(RESPONSE_PARAM_CURRENT_TIME, formatValue(formatTime(currentTime)));
        response.put(RESPONSE_PARAM_UP_TIME, formatValue(formatDuration(
                Duration.between(startTime, currentTime)
        )));

        response.put(RESPONSE_PARAM_DEPENDENCIES, formatValue(dependencyStates));

        return Collections.unmodifiableMap(response);
    }

    public void setTimeout(int timeout) {
        this.timeout = timeout;
    }

    private void setApplicationBuildProperties() {
        BuildProperties buildProperties = context.getBean(BuildProperties.class);

        appName = buildProperties.getName();
        appVersion = buildProperties.getVersion();
        buildTime = getDateAsInstant(buildProperties.getTime());
    }

    private void setApplicationGitProperties() {
        GitProperties gitProperties = context.getBean(GitProperties.class);

        commitId = gitProperties.getCommitId();
        commitBranch = gitProperties.getBranch();
    }

    private static Instant getCurrentTime() {
        return Instant.now();
    }

    private static Instant getDateAsInstant(Date date) {
        return (date != null) ? date.toInstant() : null;
    }

    private static Object formatTime(Instant instant) {
        return (instant != null) ? instant.toString() : null;
    }

    private static Object formatDuration(Duration duration) {
        return (duration != null) ? duration.toString() : null;
    }

    private static Object formatValue(Object value) {
        return (value != null) ? value : NOT_AVAILABLE;
    }

    public enum Status {

        DOWN, UP;

        public static Status mapFrom(org.springframework.boot.actuate.health.Status status) {
            if (status == org.springframework.boot.actuate.health.Status.UP) return UP;
            else return DOWN;
        }
    }

    public class Dependency {

        final String name;
        final Supplier<Status> statusProvider;

        Dependency(String name, Supplier<Status> statusProvider) {
            this.name = name;
            this.statusProvider = statusProvider;
        }

        public Map<String, Object> getCurrentState() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put(RESPONSE_PARAM_STATUS, formatValue(statusProvider.get()));
            map.put(RESPONSE_PARAM_NAME, formatValue(name));
            return Collections.unmodifiableMap(map);
        }
    }

    private Dependency createServiceRegistryDependency() {
        try {
            final DataSourceHealthIndicator dataSourceHealthIndicator = new DataSourceHealthIndicator(
                    ((JpaTransactionManager) context.getBean("transactionManagerServiceReg")).getDataSource()
            );
            return new Dependency(DEPENDENCY_NAME_SERVICE_REGISTRY, () ->
                Status.mapFrom(dataSourceHealthIndicator.health().getStatus())
            );
        } catch (RuntimeException e) {
            LOGGER.error("Failed to reach " + DEPENDENCY_NAME_SERVICE_REGISTRY + " data source", e);
            return new Dependency(DEPENDENCY_NAME_SERVICE_REGISTRY, () -> Status.DOWN);
        }
    }

    private Dependency createEidasClientDependency() {
        return new Dependency(DEPENDENCY_NAME_EIDAS_CLIENT, () -> {
            HttpGet httpGet = new HttpGet(eidasHeartbeatUrl);
            try (CloseableHttpResponse response = httpClient.execute(httpGet)) {
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_OK) {
                    return readStatusFromResponseOrReturnDown(response);
                }
            } catch (IOException e) {
                LOGGER.error(String.format("Failed to establish connection to '%s'", eidasHeartbeatUrl), e);
            }

            return Status.DOWN;
        });
    }

    private Status readStatusFromResponseOrReturnDown(HttpResponse response) {
        try {
            String jsonString = EntityUtils.toString(response.getEntity());
            JsonNode json = new ObjectMapper().readTree(jsonString);
            String statusString = json.get("status").asText();

            if (Status.UP.name().equals(statusString))
                return Status.UP;
        } catch (Exception e) {
            LOGGER.error(String.format("Failed to read status from the response from '%s'", eidasHeartbeatUrl), e);
        }

        return Status.DOWN;
    }

}
