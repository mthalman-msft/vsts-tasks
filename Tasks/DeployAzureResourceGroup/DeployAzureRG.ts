/// <reference path="../../definitions/node.d.ts" /> 
/// <reference path="../../definitions/Q.d.ts" /> 
/// <reference path="../../definitions/vsts-task-lib.d.ts" /> 
 
import path = require("path");
import tl = require("vsts-task-lib/task");
import fs = require("fs");
import util = require("util");

var msRestAzure = require("ms-rest-azure");

import virtualMachine = require("./VirtualMachine");
import resourceGroup = require("./ResourceGroup");
import env = require("./Environment");

try {
    tl.setResourcePath(path.join( __dirname, "task.json"));
}
catch (err) {
    tl.setResult(tl.TaskResult.Failed, tl.loc("TaskNotFound", err));
    process.exit();
}

export class AzureResourceGroupDeployment {

    private action:string;
    private resourceGroupName:string;
    private location:string;
    private csmFile:string;
    private csmParametersFile:string;
    private overrideParameters:string;
    private enableDeploymentPrerequisites:boolean;
    private outputVariable:string;
    private subscriptionId:string;
    private connectedService:string;
    private isLoggedIn:boolean = false;
    private deploymentMode:string;
    
    constructor() {
        try { 
            this.connectedService = null;
            this.connectedService = tl.getInput("ConnectedServiceName");
            this.action = tl.getInput("action");
            this.resourceGroupName = tl.getInput("resourceGroupName");
            this.location = tl.getInput("location");
            this.csmFile = tl.getPathInput("csmFile");
            this.csmParametersFile = tl.getPathInput("csmParametersFile");
            this.overrideParameters = tl.getInput("overrideParameters");
            this.enableDeploymentPrerequisites = tl.getBoolInput("enableDeploymentPrerequisites");
            this.outputVariable = tl.getInput("outputVariable");
            this.subscriptionId = tl.getEndpointDataParameter(this.connectedService, "SubscriptionId", true);    
            this.deploymentMode = tl.getInput("deploymentMode");
        }
        catch (error) {
            tl.setResult(tl.TaskResult.Failed, tl.loc("ARGD_ConstructorFailed", error.message));
        }
    }

    public execute() {
        switch (this.action) {
           case "Create Or Update Resource Group": 
           case "DeleteRG":
           case "Select Resource Group":
                new resourceGroup.ResourceGroup(this.action, this.connectedService, this.getARMCredentials(), this.resourceGroupName, this.location, this.csmFile, this.csmParametersFile, this.overrideParameters, this.subscriptionId, this.deploymentMode, this.outputVariable);
                break;
           case "Start":
           case "Stop":
           case "Restart":
           case "Delete":
               new virtualMachine.VirtualMachine(this.resourceGroupName, this.action, this.subscriptionId, this.connectedService, this.getARMCredentials());
               break;
           default:
               tl.setResult(tl.TaskResult.Succeeded, tl.loc("InvalidAction"));
        }
    }

     private getARMCredentials() {
        var endpointAuth = tl.getEndpointAuthorization(this.connectedService, true);
        var servicePrincipalId:string = endpointAuth.parameters["serviceprincipalid"];
        var servicePrincipalKey:string = endpointAuth.parameters["serviceprincipalkey"];
        var tenantId:string = endpointAuth.parameters["tenantid"];
        var credentials = new msRestAzure.ApplicationTokenCredentials(servicePrincipalId, tenantId, servicePrincipalKey);
        return credentials;
    }
}


var azureResourceGroupDeployment = new AzureResourceGroupDeployment();
azureResourceGroupDeployment.execute();