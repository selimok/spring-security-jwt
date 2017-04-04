package software.sandc.springframework.security.jwt.model;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.ObjectCodec;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

public class JWTAuthenticationSerializer extends JsonDeserializer<JWTAuthentication> {

    @Override
    public JWTAuthentication deserialize(JsonParser jsonParser, DeserializationContext ctxt) throws IOException,
            JsonProcessingException {

        boolean authenticated = false;
        String principal = null;
        String sessionId = null;
        List<GrantedAuthority> authorities = null;

        ObjectCodec oc = jsonParser.getCodec();
        JsonNode node = oc.readTree(jsonParser);

        JsonNode authenticatedNode = node.get("authenticated");
        if (authenticatedNode != null) {
            authenticated = authenticatedNode.booleanValue();
        }

        JsonNode principalNode = node.get("principal");
        if (principalNode != null) {
            principal = principalNode.asText();
        }

        JsonNode sessionIdNode = node.get("sessionId");
        if (sessionIdNode != null) {
            sessionId = sessionIdNode.asText();
        }

        JsonNode authoritiesNodes = node.get("authorities");
        if (authoritiesNodes != null) {
            ArrayList<GrantedAuthority> tempAuthorities = new ArrayList<GrantedAuthority>(authoritiesNodes.size());
            Iterator<JsonNode> authoritiesNodesIterator = authoritiesNodes.elements();
            while (authoritiesNodesIterator.hasNext()) {
                JsonNode next = authoritiesNodesIterator.next();
                JsonNode authority = next.get("authority");
                SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(authority.asText());
                tempAuthorities.add(simpleGrantedAuthority);
            }

            authorities = Collections.unmodifiableList(tempAuthorities);
        }

        JWTAuthentication jwtAuthentication = new JWTAuthentication(principal, sessionId, authorities);
        jwtAuthentication.setAuthenticated(authenticated);
        return jwtAuthentication;

    }

}
