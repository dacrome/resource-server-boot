package org.osiam.resource_server.resources.controller;

import java.util.List;

import org.osiam.resource_server.resources.provisioning.SCIMExtensionProvisioning;
import org.osiam.resource_server.resources.provisioning.model.ExtensionDefinition;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * This controller contains osiam specific interfaces.
 */
@Controller
@RequestMapping(value = "/osiam")
public class OsiamController {

    @Autowired
    private SCIMExtensionProvisioning extensionProvisioning;

    /**
     * This handler is responsible for getting all existing extension definitions.
     *
     * @return The list with all extension definitions.
     */
    @RequestMapping(value = "/extension-definition", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public List<ExtensionDefinition> getAllExtensions() {
        return extensionProvisioning.getAllExtensionDefinitions();
    }
}
