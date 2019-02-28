package ee.ria.sso.flow;

import org.springframework.web.servlet.ModelAndView;
import org.springframework.webflow.core.collection.LocalAttributeMap;
import org.springframework.webflow.execution.Action;
import org.springframework.webflow.execution.ActionExecutionException;
import org.springframework.webflow.execution.RequestContext;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractFlowExecutionException extends ActionExecutionException {

    protected final transient ModelAndView modelAndView;

    public AbstractFlowExecutionException(String flowId, ModelAndView modelAndView, Exception e) {
        super(flowId, null, null, new LocalAttributeMap(), e);
        this.modelAndView = modelAndView;
    }

    public AbstractFlowExecutionException(RequestContext context, Action action, ModelAndView modelAndView, Exception e) {
        super(context.getActiveFlow().getId(), context.getCurrentState() != null ? context.getCurrentState().getId() : null, action, context.getAttributes(), e);
        this.modelAndView = modelAndView;
    }

    /*
     * ACCESSORS
     */

    public ModelAndView getModelAndView() {
        return this.modelAndView;
    }

}
