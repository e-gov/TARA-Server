package org.apereo.cas.config;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.naming.OperationNotSupportedException;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.web.flow.CasDefaultFlowUrlHandler;
import org.apereo.cas.web.flow.CasWebflowConfigurer;
import org.apereo.cas.web.flow.LogoutConversionService;
import org.apereo.spring.webflow.plugin.ClientFlowExecutionRepository;
import org.apereo.spring.webflow.plugin.EncryptedTranscoder;
import org.apereo.spring.webflow.plugin.Transcoder;
import org.cryptacular.bean.CipherBean;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.binding.convert.ConversionService;
import org.springframework.binding.expression.ExpressionParser;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.servlet.HandlerAdapter;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.ViewResolver;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.webflow.config.FlowBuilderServicesBuilder;
import org.springframework.webflow.config.FlowDefinitionRegistryBuilder;
import org.springframework.webflow.config.FlowExecutorBuilder;
import org.springframework.webflow.context.servlet.FlowUrlHandler;
import org.springframework.webflow.conversation.impl.SessionBindingConversationManager;
import org.springframework.webflow.definition.registry.FlowDefinitionRegistry;
import org.springframework.webflow.engine.builder.ViewFactoryCreator;
import org.springframework.webflow.engine.builder.support.FlowBuilderServices;
import org.springframework.webflow.engine.impl.FlowExecutionImplFactory;
import org.springframework.webflow.execution.repository.impl.DefaultFlowExecutionRepository;
import org.springframework.webflow.execution.repository.snapshot.SerializedFlowExecutionSnapshotFactory;
import org.springframework.webflow.executor.FlowExecutor;
import org.springframework.webflow.executor.FlowExecutorImpl;
import org.springframework.webflow.expression.spel.WebFlowSpringELExpressionParser;
import org.springframework.webflow.mvc.builder.MvcViewFactoryCreator;
import org.springframework.webflow.mvc.servlet.FlowHandler;
import org.springframework.webflow.mvc.servlet.FlowHandlerAdapter;
import org.springframework.webflow.mvc.servlet.FlowHandlerMapping;

import com.google.common.base.Throwables;

import ee.ria.sso.flow.TaraWebflowConfigurer;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

@Configuration("casWebflowContextConfiguration")
@EnableConfigurationProperties({CasConfigurationProperties.class})
public class CasWebflowContextConfiguration {

    private static final int LOGOUT_FLOW_HANDLER_ORDER = 3;
    private static final String BASE_CLASSPATH_WEBFLOW = "classpath*:/webflow";

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("registeredServiceViewResolver")
    private ViewResolver registeredServiceViewResolver;

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    @Qualifier("webflowCipherExecutor")
    private CipherExecutor webflowCipherExecutor;

    public CasWebflowContextConfiguration() {
    }

    @Bean
    public ExpressionParser expressionParser() {
        return new WebFlowSpringELExpressionParser(new SpelExpressionParser(), this.logoutConversionService());
    }

    @Bean
    public ConversionService logoutConversionService() {
        return new LogoutConversionService();
    }

    @RefreshScope
    @Bean
    public ViewFactoryCreator viewFactoryCreator() {
        MvcViewFactoryCreator resolver = new MvcViewFactoryCreator();
        resolver.setViewResolvers(Collections.singletonList(this.registeredServiceViewResolver));
        return resolver;
    }

    @Bean
    public FlowUrlHandler loginFlowUrlHandler() {
        return new CasDefaultFlowUrlHandler();
    }

    @Bean
    public FlowUrlHandler logoutFlowUrlHandler() {
        CasDefaultFlowUrlHandler handler = new CasDefaultFlowUrlHandler();
        handler.setFlowExecutionKeyParameter("RelayState");
        return handler;
    }

    @RefreshScope
    @Bean
    public HandlerAdapter logoutHandlerAdapter() {
        FlowHandlerAdapter handler = new FlowHandlerAdapter() {
            public boolean supports(Object handler) {
                return super.supports(handler) && ((FlowHandler) handler).getFlowId().equals("logout");
            }
        };
        handler.setFlowExecutor(this.logoutFlowExecutor());
        handler.setFlowUrlHandler(this.logoutFlowUrlHandler());
        return handler;
    }

    @RefreshScope
    @Bean
    public CipherBean loginFlowCipherBean() {
        try {
            return new CipherBean() {
                public byte[] encrypt(byte[] bytes) {
                    return (byte[]) ((byte[]) CasWebflowContextConfiguration.this.webflowCipherExecutor.encode(bytes));
                }

                public void encrypt(InputStream inputStream, OutputStream outputStream) {
                    throw new RuntimeException(new OperationNotSupportedException("Encrypting input stream is not supported"));
                }

                public byte[] decrypt(byte[] bytes) {
                    return (byte[]) ((byte[]) CasWebflowContextConfiguration.this.webflowCipherExecutor.decode(bytes));
                }

                public void decrypt(InputStream inputStream, OutputStream outputStream) {
                    throw new RuntimeException(new OperationNotSupportedException("Decrypting input stream is not supported"));
                }
            };
        } catch (Exception var2) {
            throw Throwables.propagate(var2);
        }
    }

    @RefreshScope
    @Bean
    public FlowBuilderServices builder() {
        FlowBuilderServicesBuilder builder = new FlowBuilderServicesBuilder(this.applicationContext);
        builder.setViewFactoryCreator(this.viewFactoryCreator());
        builder.setExpressionParser(this.expressionParser());
        builder.setDevelopmentMode(this.casProperties.getWebflow().isRefresh());
        return builder.build();
    }

    @Bean
    public Transcoder loginFlowStateTranscoder() {
        try {
            return new EncryptedTranscoder(this.loginFlowCipherBean());
        } catch (Exception var2) {
            throw new BeanCreationException(var2.getMessage(), var2);
        }
    }

    @Bean
    public HandlerAdapter loginHandlerAdapter() {
        FlowHandlerAdapter handler = new FlowHandlerAdapter() {
            public boolean supports(Object handler) {
                return super.supports(handler) && ((FlowHandler) handler).getFlowId().equals("login");
            }
        };
        handler.setFlowExecutor(this.loginFlowExecutor());
        handler.setFlowUrlHandler(this.loginFlowUrlHandler());
        return handler;
    }

    @RefreshScope
    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor bean = new LocaleChangeInterceptor();
        bean.setParamName(this.casProperties.getLocale().getParamName());
        return bean;
    }

    @Bean
    public HandlerMapping logoutFlowHandlerMapping() {
        FlowHandlerMapping handler = new FlowHandlerMapping();
        handler.setOrder(3);
        handler.setFlowRegistry(this.logoutFlowRegistry());
        Object[] interceptors = new Object[]{this.localeChangeInterceptor()};
        handler.setInterceptors(interceptors);
        return handler;
    }

    @Lazy
    @Bean
    public Object[] loginFlowHandlerMappingInterceptors() {
        List interceptors = new ArrayList();
        interceptors.add(this.localeChangeInterceptor());
        if (this.applicationContext.containsBean("authenticationThrottle")) {
            interceptors.add(this.applicationContext.getBean("authenticationThrottle", HandlerInterceptor.class));
        }

        return interceptors.toArray();
    }

    @Bean
    public HandlerMapping loginFlowHandlerMapping() {
        FlowHandlerMapping handler = new FlowHandlerMapping();
        handler.setOrder(2);
        handler.setFlowRegistry(this.loginFlowRegistry());
        handler.setInterceptors(this.loginFlowHandlerMappingInterceptors());
        return handler;
    }

    @RefreshScope
    @Bean
    public FlowExecutor logoutFlowExecutor() {
        FlowExecutorBuilder builder = new FlowExecutorBuilder(this.logoutFlowRegistry(), this.applicationContext);
        builder.setAlwaysRedirectOnPause(this.casProperties.getWebflow().isAlwaysPauseRedirect());
        builder.setRedirectInSameState(this.casProperties.getWebflow().isRedirectSameState());
        return builder.build();
    }

    @Bean
    public FlowDefinitionRegistry logoutFlowRegistry() {
        FlowDefinitionRegistryBuilder builder = new FlowDefinitionRegistryBuilder(this.applicationContext, this.builder());
        builder.setBasePath("classpath*:/webflow");
        builder.addFlowLocationPattern("/logout/*-webflow.xml");
        return builder.build();
    }

    @Bean
    public FlowDefinitionRegistry loginFlowRegistry() {
        FlowDefinitionRegistryBuilder builder = new FlowDefinitionRegistryBuilder(this.applicationContext, this.builder());
        builder.setBasePath("classpath*:/webflow");
        builder.addFlowLocationPattern("/login/*-webflow.xml");
        return builder.build();
    }

    @RefreshScope
    @Bean
    public FlowExecutor loginFlowExecutor() {
        return this.casProperties.getWebflow().getSession().isStorage() ? this.flowExecutorViaServerSessionBindingExecution() : this.flowExecutorViaClientFlowExecution();
    }

    @Bean
    public FlowExecutor flowExecutorViaServerSessionBindingExecution() {
        FlowDefinitionRegistry loginFlowRegistry = this.loginFlowRegistry();
        SessionBindingConversationManager conversationManager = new SessionBindingConversationManager();
        conversationManager.setLockTimeoutSeconds((int)this.casProperties.getWebflow().getSession().getLockTimeout());
        conversationManager.setMaxConversations(this.casProperties.getWebflow().getSession().getMaxConversations());
        FlowExecutionImplFactory executionFactory = new FlowExecutionImplFactory();
        SerializedFlowExecutionSnapshotFactory flowExecutionSnapshotFactory = new SerializedFlowExecutionSnapshotFactory(executionFactory, loginFlowRegistry);
        flowExecutionSnapshotFactory.setCompress(this.casProperties.getWebflow().getSession().isCompress());
        DefaultFlowExecutionRepository repository = new DefaultFlowExecutionRepository(conversationManager, flowExecutionSnapshotFactory);
        executionFactory.setExecutionKeyFactory(repository);
        return new FlowExecutorImpl(loginFlowRegistry, executionFactory, repository);
    }

    @Bean
    public FlowExecutor flowExecutorViaClientFlowExecution() {
        FlowDefinitionRegistry loginFlowRegistry = this.loginFlowRegistry();
        ClientFlowExecutionRepository repository = new ClientFlowExecutionRepository();
        repository.setFlowDefinitionLocator(loginFlowRegistry);
        repository.setTranscoder(this.loginFlowStateTranscoder());
        FlowExecutionImplFactory factory = new FlowExecutionImplFactory();
        factory.setExecutionKeyFactory(repository);
        repository.setFlowExecutionFactory(factory);
        return new FlowExecutorImpl(loginFlowRegistry, factory, repository);
    }

    @ConditionalOnMissingBean(
        name = {"defaultWebflowConfigurer"}
    )
    @Bean
    public CasWebflowConfigurer defaultWebflowConfigurer() {
        TaraWebflowConfigurer c = new TaraWebflowConfigurer(this.builder(), this.loginFlowRegistry());
        c.setLogoutFlowDefinitionRegistry(this.logoutFlowRegistry());
        return c;
    }

}
