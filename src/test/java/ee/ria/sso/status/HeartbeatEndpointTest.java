package ee.ria.sso.status;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import ee.ria.sso.config.eidas.EidasConfigurationProvider;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.info.GitProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.test.util.ReflectionTestUtils;

import javax.sql.DataSource;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAmount;
import java.util.List;
import java.util.Map;

public class HeartbeatEndpointTest {

    private static final int EIDAS_CLIENT_PORT = 7171;
    private static final WireMockServer wireMockServer = new WireMockServer(
            WireMockConfiguration.wireMockConfig().port(EIDAS_CLIENT_PORT)
    );

    @BeforeClass
    public static void setUp() {
        wireMockServer.start();
    }

    @AfterClass
    public static void tearDown() {
        wireMockServer.stop();
    }

    @Test
    public void invoke_validBuildProperties_shouldReturnValidBuildProperties() {
        String applicationName = "Application Name";
        String applicationVersion = "1.0.0";
        Instant buildTime = Instant.now();

        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        BuildProperties buildProperties = createMockBuildProperties(applicationName, applicationVersion, buildTime);
        Mockito.when(context.getBean(BuildProperties.class)).thenReturn(buildProperties);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultBuildProperties(result, applicationName, applicationVersion, buildTime.toString());
    }

    @Test
    public void invoke_buildPropertiesThrowsException_shouldReturnEmptyBuildProperties() {
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        Mockito.when(context.getBean(BuildProperties.class)).thenThrow(RuntimeException.class);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultBuildProperties(result, "N/A", "N/A", "N/A");
    }

    @Test
    public void invoke_validGitProperties_shouldReturnValidGitProperties() {
        String commitId = "hw82gsj40ghjwh39fk";
        String commitBranch = "branch_name";

        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        GitProperties gitProperties = createMockGitProperties(commitId, commitBranch);
        Mockito.when(context.getBean(GitProperties.class)).thenReturn(gitProperties);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultGitProperties(result, commitBranch, commitId);
    }

    @Test
    public void invoke_gitPropertiesThrowsException_shouldReturnEmptyGitProperties() {
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        Mockito.when(context.getBean(GitProperties.class)).thenThrow(RuntimeException.class);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultGitProperties(result, "N/A", "N/A");
    }

    @Test
    public void invoke_startTime_shouldReturnValidStartTime() {
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Instant currentTime = Instant.now();

        Map<String, Object> result = heartbeatEndpoint.invoke();
        validateHeartBeatResultMap(result);
        validateTimeWithDelta(String.format("startTime should match %s", currentTime),
                currentTime, Instant.parse((String) result.get("startTime")), Duration.ofMinutes(1));
    }

    @Test
    public void invoke_currentTime_shouldReturnValidCurrentTime() {
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();
        Instant currentTime = Instant.now();

        validateHeartBeatResultMap(result);
        validateTimeWithDelta(String.format("currentTime should match %s", currentTime),
                currentTime, Instant.parse((String) result.get("currentTime")), Duration.ofMinutes(1));
    }

    @Test
    public void invoke_serviceRegistryRespondsHealthy_shouldReturnServiceRegistryStatusUp() {
        JpaTransactionManager jpaTransactionManager = createMockJpaTransactionManagerWith(createMockDataSource());

        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        Mockito.when(context.getBean("transactionManagerServiceReg")).thenReturn(jpaTransactionManager);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context);
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultDependencyStatus(result, "JPA Service Registry", "UP");
    }

    private DataSource createMockDataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUrl("jdbc:h2:mem:db;DB_CLOSE_DELAY=-1");
        dataSource.setUsername("cas");
        dataSource.setPassword("cas");

        return dataSource;
    }

    @Test
    public void invoke_eidasClientRespondsUp_shouldReturnEidasClientStatusUp() {
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(Mockito.mock(ApplicationContext.class),
                String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));

        updateWireMockHeartbeatResponse(200, "UP");

        Map<String, Object> result = heartbeatEndpoint.invoke();
        validateHeartBeatResultMap(result);
        validateHeartbeatResultDependencyStatus(result, "eIDAS-Client", "UP");
    }

    @Test
    public void invoke_eidasClientRespondsDown_shouldReturnEidasClientStatusDown() {
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(Mockito.mock(ApplicationContext.class),
                String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));

        updateWireMockHeartbeatResponse(200, "DOWN");

        Map<String, Object> result = heartbeatEndpoint.invoke();
        validateHeartBeatResultMap(result);
        validateHeartbeatResultDependencyStatus(result, "eIDAS-Client", "DOWN");
    }

    @Test
    public void invoke_eidasClientRespondsIvalidJson_shouldReturnEidasClientStatusDown() {
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(Mockito.mock(ApplicationContext.class),
                String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));

        wireMockServer.stubFor(WireMock.get("/heartbeat")
                .willReturn(WireMock.aResponse()
                        .withStatus(200)
                        .withBody("plain text")
                )
        );

        Map<String, Object> result = heartbeatEndpoint.invoke();
        validateHeartBeatResultMap(result);
        validateHeartbeatResultDependencyStatus(result, "eIDAS-Client", "DOWN");
    }

    @Test
    public void invoke_eidasClientRespondsError_shouldReturnEidasClientStatusDown() {
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(Mockito.mock(ApplicationContext.class),
                String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));

        wireMockServer.stubFor(WireMock.get("/heartbeat")
                .willReturn(WireMock.aResponse()
                        .withStatus(500)
                )
        );

        Map<String, Object> result = heartbeatEndpoint.invoke();
        validateHeartBeatResultMap(result);
        validateHeartbeatResultDependencyStatus(result, "eIDAS-Client", "DOWN");
    }

    @Test
    public void invoke_ServiceRegistryAndEidasClientRespondUp_shouldReturnStatusUp() {
        JpaTransactionManager jpaTransactionManager = createMockJpaTransactionManagerWith(createMockDataSource());
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        Mockito.when(context.getBean("transactionManagerServiceReg")).thenReturn(jpaTransactionManager);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context, String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));
        updateWireMockHeartbeatResponse(200, "UP");
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultGrlobalStatus(result, "UP");
    }

    @Test
    public void invoke_ServiceRegistryUpAndEidasClientDown_shouldReturnStatusDown() {
        JpaTransactionManager jpaTransactionManager = createMockJpaTransactionManagerWith(createMockDataSource());
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        Mockito.when(context.getBean("transactionManagerServiceReg")).thenReturn(jpaTransactionManager);

        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context, String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));
        updateWireMockHeartbeatResponse(200, "DOWN");
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultGrlobalStatus(result, "DOWN");
    }

    @Test
    public void invoke_ServiceRegistryMissingAndEidasClientUp_shouldReturnStatusDown() {
        ApplicationContext context = Mockito.mock(ApplicationContext.class);
        HeartbeatEndpoint heartbeatEndpoint = createHeartbeatWith(context, String.format("http://localhost:%d/heartbeat", EIDAS_CLIENT_PORT));
        updateWireMockHeartbeatResponse(200, "UP");
        Map<String, Object> result = heartbeatEndpoint.invoke();

        validateHeartBeatResultMap(result);
        validateHeartbeatResultGrlobalStatus(result, "DOWN");
    }

    private HeartbeatEndpoint createHeartbeatWith(ApplicationContext context) {
        return createHeartbeatWith(context, null);
    }

    private HeartbeatEndpoint createHeartbeatWith(ApplicationContext context, String eidasHeartbeatUrl) {
        HeartbeatEndpoint heartbeatEndpoint = new HeartbeatEndpoint();
        ReflectionTestUtils.setField(heartbeatEndpoint, "context", context);
        ReflectionTestUtils.setField(heartbeatEndpoint, "eidasHeartbeatUrl", eidasHeartbeatUrl);
        heartbeatEndpoint.setUp();
        return heartbeatEndpoint;
    }

    private BuildProperties createMockBuildProperties(String applicationName, String applicationVersion, Instant buildTime) {
        BuildProperties buildProperties = Mockito.mock(BuildProperties.class);
        Mockito.when(buildProperties.getName()).thenReturn(applicationName);
        Mockito.when(buildProperties.getVersion()).thenReturn(applicationVersion);
        Mockito.when(buildProperties.getTime()).thenReturn(Date.from(buildTime));
        return buildProperties;
    }

    private GitProperties createMockGitProperties(String commitId, String commitBranch) {
        GitProperties gitProperties = Mockito.mock(GitProperties.class);
        Mockito.when(gitProperties.getCommitId()).thenReturn(commitId);
        Mockito.when(gitProperties.getBranch()).thenReturn(commitBranch);
        return gitProperties;
    }

    private JpaTransactionManager createMockJpaTransactionManagerWith(DataSource dataSource) {
        JpaTransactionManager jpaTransactionManager = Mockito.mock(JpaTransactionManager.class);
        Mockito.when(jpaTransactionManager.getDataSource()).thenReturn(dataSource);
        return jpaTransactionManager;
    }

    private void validateHeartBeatResultMap(Map<String, Object> map) {
        Assert.assertEquals("Heartbeat result map should contain 10 entries", 10, map.size());
        Assert.assertTrue("Heartbeat result map should contain \"status\" entry", map.containsKey("status"));
        Assert.assertTrue("Heartbeat result map should contain \"name\" entry", map.containsKey("name"));
        Assert.assertTrue("Heartbeat result map should contain \"version\" entry", map.containsKey("version"));
        Assert.assertTrue("Heartbeat result map should contain \"commitId\" entry", map.containsKey("commitId"));
        Assert.assertTrue("Heartbeat result map should contain \"commitBranch\" entry", map.containsKey("commitBranch"));
        Assert.assertTrue("Heartbeat result map should contain \"buildTime\" entry", map.containsKey("buildTime"));
        Assert.assertTrue("Heartbeat result map should contain \"startTime\" entry", map.containsKey("startTime"));
        Assert.assertTrue("Heartbeat result map should contain \"currentTime\" entry", map.containsKey("currentTime"));
        Assert.assertTrue("Heartbeat result map should contain \"uptime\" entry", map.containsKey("uptime"));
        Assert.assertTrue("Heartbeat result map should contain \"dependencies\" entry", map.containsKey("dependencies"));
    }

    private void validateHeartbeatResultBuildProperties(Map<String, Object> result, String applicationName, String applicationVersion, String buildTime) {
        Assert.assertEquals("Invalid name", applicationName, result.get("name"));
        Assert.assertEquals("Invalid version", applicationVersion, result.get("version"));
        Assert.assertEquals("Invalid buildTime", buildTime, result.get("buildTime"));
    }

    private void validateHeartbeatResultGitProperties(Map<String, Object> result, String commitBranch, String commitId) {
        Assert.assertEquals("Invalid commit ID", commitId, result.get("commitId"));
        Assert.assertEquals("Invalid branch", commitBranch, result.get("commitBranch"));
    }

    private void validateHeartbeatResultDependencyStatus(Map<String, Object> result, String dependencyName, String status) {
        Map<String, Object> eidasClientDependency = findNamedDependencyFromHeartbeatResultMap(result, dependencyName);
        Assert.assertNotNull(String.format("%s dependency should exist", dependencyName), eidasClientDependency);
        Assert.assertEquals(String.format("%s status should be \"%s\"", dependencyName, status),
                HeartbeatEndpoint.Status.valueOf(status),
                eidasClientDependency.get("status"));
    }

    private void validateHeartbeatResultGrlobalStatus(Map<String, Object> result, String status) {
        Assert.assertEquals(String.format("Heartbeat status should be \"%s\"", status),
                HeartbeatEndpoint.Status.valueOf(status),
                result.get("status"));
    }

    private void validateTimeWithDelta(String message, Instant expected, Instant actual, TemporalAmount delta) {
        double expectedSeconds = (double) expected.getEpochSecond();
        double actualSeconds = (double) actual.getEpochSecond();
        double deltaSeconds = (double) delta.get(ChronoUnit.SECONDS);
        Assert.assertEquals(message, expectedSeconds, actualSeconds, deltaSeconds);
    }

    private Map<String, Object> findNamedDependencyFromHeartbeatResultMap(Map<String, Object> result, String name) {
        List<Map<String, Object>> dependencyList = findDependencyListFromHeartbeatResultMap(result);
        Assert.assertNotNull("Dependency list should exist", dependencyList);

        return dependencyList.stream().filter(d -> name.equals(d.get("name"))).findFirst().get();
    }

    private List<Map<String, Object>> findDependencyListFromHeartbeatResultMap(Map<String, Object> result) {
        return (List<Map<String, Object>>) result.get("dependencies");
    }

    private void updateWireMockHeartbeatResponse(int httpStatusCode, String heartbeatStatus) {
        wireMockServer.stubFor(WireMock.get("/heartbeat")
                .willReturn(WireMock.aResponse()
                        .withStatus(httpStatusCode)
                        .withBody(String.format("{\"status\":\"%s\"}", heartbeatStatus))
                )
        );
    }
}