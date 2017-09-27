package ee.ria.sso;

import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

/**
 * Created by serkp on 8.09.2017.
 */

public class AttributesService {

	public Map<String, Object> getAttributesByPersonalCode(String idCode) {
		if (StringUtils.isEmpty(idCode))
			throw new IllegalArgumentException("ID code cannot be NULL or empty");
		final Map<String, Object> attributes = new LinkedHashMap<>();
		attributes.put(AttributeConstant.PERSONAL_CODE.getKey(), idCode);
		return attributes;
	}
}