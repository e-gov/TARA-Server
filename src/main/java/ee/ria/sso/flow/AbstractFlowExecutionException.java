package ee.ria.sso.flow;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.view.AbstractView;

/**
 * Created by Janar Rahumeel (CGI Estonia)
 */

public abstract class AbstractFlowExecutionException extends RuntimeException {

    private final AbstractView view;
    private final HttpStatus status;
    private final Map<String, ?> model;

    public AbstractFlowExecutionException(AbstractView view, Map<String, ?> model, HttpStatus status, Exception e) {
        super(e);
        this.view = view;
        this.model = model;
        this.status = status;
    }

    /*
     * ACCESSORS
     */

    public HttpStatus getStatus() {
        return status;
    }

    public Map<String, ?> getModel() {
        return model;
    }

    public AbstractView getView() {
        return view;
    }

}
