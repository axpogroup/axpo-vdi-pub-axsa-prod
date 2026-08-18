function IsHostOrSubdomain(host, domain) {
    return host == domain || dnsDomainIs(host, "." + domain);
}

function FindProxyForURL(url, host) {
    // 1. Cheap, no-DNS checks FIRST
    if (
        isPlainHostName(host) ||
        host == "localhost" ||
        host == "127.0.0.1"
    ) {
        return "DIRECT";
    }

    // No proxy for Microsoft 365, file share and Datto
    if (
        shExpMatch(host, "*.microsoft.com") ||
        shExpMatch(host, "*.msftidentity.com") ||
        shExpMatch(host, "*.msidentity.com") ||
        shExpMatch(host, "*.windowsazure.com") ||
        shExpMatch(host, "*.windows.net") ||
        shExpMatch(host, "*.microsoftonline.com") ||
        shExpMatch(host, "*.microsoftazuread-sso.com") ||
        shExpMatch(host, "*.microsoftonline-p.net") ||
        shExpMatch(host, "*.microsoftonline-p.com") ||
        shExpMatch(host, "*.aspnetcdn.com") ||
        shExpMatch(host, "*.live.net") ||
        shExpMatch(host, "*.live.com") ||
        shExpMatch(host, "*.onedrive.com") ||
        shExpMatch(host, "*.onenote.com") ||
        shExpMatch(host, "*.office.net") ||
        shExpMatch(host, "*.office.com") ||
        shExpMatch(host, "*.azureedge.net") ||
        shExpMatch(host, "*.azure.net") ||
        shExpMatch(host, "*.microsoftstream.com") ||
        shExpMatch(host, "*.msauth.net") ||
        shExpMatch(host, "*.msauthimages.net") ||
        shExpMatch(host, "*.msecnd.net") ||
        shExpMatch(host, "*.msftauth.net") ||
        shExpMatch(host, "*.msftauthimages.net") ||
        shExpMatch(host, "*.phonefactor.net") ||
        shExpMatch(host, "*.cloudappsecurity.com") ||
        shExpMatch(host, "*.oaspapps.com") ||
        shExpMatch(host, "*.akadns.net") ||
        shExpMatch(host, "*.o365weve.com") ||
        shExpMatch(host, "*.onestore.ms") ||
        shExpMatch(host, "*.gfx.ms") ||
        shExpMatch(host, "*.linkedin.com") ||
        shExpMatch(host, "*.msocdn.com") ||
        shExpMatch(host, "*.office365.com") ||
        shExpMatch(host, "*.aadrm.com") ||
        shExpMatch(host, "*.azurerms.com") ||
        shExpMatch(host, "*.azure.com") ||
        shExpMatch(host, "*.sharepointonline.com") ||
        shExpMatch(host, "*.staffhub.ms") ||
        shExpMatch(host, "*.edgesuite.net") ||
        shExpMatch(host, "*.acompli.net") ||
        shExpMatch(host, "*.outlookmobile.com") ||
        shExpMatch(host, "*.windows-ppe.net") ||
        shExpMatch(host, "*.getmicrosoftkey.com") ||
        shExpMatch(host, "*.yammer.com") ||
        shExpMatch(host, "*.yammerusercontent.com") ||
        shExpMatch(host, "*.assets-yammer.com") ||
        shExpMatch(host, "*.outlook.com") ||
        shExpMatch(host, "*.sway-cdn.com") ||
        shExpMatch(host, "*.sway-extensions.com") ||
        shExpMatch(host, "*.sway.com") ||
        shExpMatch(host, "*.entrust.net") ||
        shExpMatch(host, "*.geotrust.com") ||
        shExpMatch(host, "*.omniroot.com") ||
        shExpMatch(host, "*.public-trust.com") ||
        shExpMatch(host, "*.symcb.com") ||
        shExpMatch(host, "*.symcd.com") ||
        shExpMatch(host, "*.verisign.com") ||
        shExpMatch(host, "*.verisign.net") ||
        shExpMatch(host, "*.identrust.com") ||
        shExpMatch(host, "*.digicert.com") ||
        shExpMatch(host, "*.letsencrypt.org") ||
        shExpMatch(host, "*.globalsign.com") ||
        shExpMatch(host, "*.globalsign.net") ||
        shExpMatch(host, "*.msocsp.com") ||
        shExpMatch(host, "*.microsoft365.com") ||
        shExpMatch(host, "*.microsoftusercontent.com") ||
        shExpMatch(host, "*.azure-apim.net") ||
        shExpMatch(host, "*.powerapps.com") ||
        shExpMatch(host, "*.powerautomate.com") ||
        shExpMatch(host, "*.windows.com") ||
        shExpMatch(host, "*.cortana.ai") ||
        shExpMatch(host, "*.cloud.microsoft") ||
        shExpMatch(host, "*.static.microsoft") ||
        shExpMatch(host, "*.usercontent.microsoft") ||
        shExpMatch(host, "*.file.core.windows.net") ||
        shExpMatch(host, "*.rmm.datto.com") ||
        shExpMatch(host, "*.centralstage.net") ||
        shExpMatch(host, "*.api.powerbi.com") ||
        shExpMatch(host, "*.businesscentral.dynamics.com") ||
        shExpMatch(host, "planta-ppm-backend.axpo.app") ||
        shExpMatch(host, "*.secure-access.axpo-systems.com") ||
        shExpMatch(host, "*.secure-portal.axpo-systems.com")
    ) {
        return "DIRECT";
    }

    // No proxy for Teams Communications
    if (
        shExpMatch(host, "*.lync.com") ||
        shExpMatch(host, "*.teams.microsoft.com") ||
        shExpMatch(host, "teams.microsoft.com") ||
        shExpMatch(host, "*.keydelivery.mediaservices.windows.net") ||
        shExpMatch(host, "*.streaming.mediaservices.windows.net") ||
        shExpMatch(host, "mlccdn.blob.core.windows.net") ||
        shExpMatch(host, "aka.ms") ||
        shExpMatch(host, "*.users.storage.live.com") ||
        shExpMatch(host, "adl.windows.com") ||
        shExpMatch(host, "*.secure.skypeassets.com") ||
        shExpMatch(host, "*.skype.com") ||
        shExpMatch(host, "compass-ssl.microsoft.com")
    ) {
        return "DIRECT";
    }

    // No proxy for EPLAN Platform, Services and Rittal Applications.
    if (
        // EPLAN Core / Identity / Auth
        IsHostOrSubdomain(host, "login.eplan.com") ||
        IsHostOrSubdomain(host, "identityservice.eplan.com") ||
        IsHostOrSubdomain(host, "useradministration.eplan.com") ||
        IsHostOrSubdomain(host, "myaccountservice.eplan.com") ||
        IsHostOrSubdomain(host, "mysettings.eplan.com") ||
        IsHostOrSubdomain(host, "selfservice.eplan.com") ||
        IsHostOrSubdomain(host, "legalnotes.eplan.com") ||
        IsHostOrSubdomain(host, "goto.eplan.com") ||
        IsHostOrSubdomain(host, "www.eplan.com") ||
        IsHostOrSubdomain(host, "www.eplan.help") ||
        // EPLAN Platform Services
        IsHostOrSubdomain(host, "fileprovider.eplan.com") ||
        IsHostOrSubdomain(host, "mgmtservice.eplan.com") ||
        IsHostOrSubdomain(host, "appsservice.eplan.com") ||
        IsHostOrSubdomain(host, "apps.eplan.com") ||
        IsHostOrSubdomain(host, "configuration.eplan.com") ||
        IsHostOrSubdomain(host, "api.eplan.com") ||
        IsHostOrSubdomain(host, "notificationservice.eplan.com") ||
        IsHostOrSubdomain(host, "licensingservice.eplan.com") ||
        IsHostOrSubdomain(host, "licensingservicev5.eplan.com") ||
        // EPLAN Data Portal, eBuild, eManage and eStock
        IsHostOrSubdomain(host, "dataportal.eplan.com") ||
        IsHostOrSubdomain(host, "ebuilddesigner.eplan.com") ||
        IsHostOrSubdomain(host, "ebuildprojectbuilder.eplan.com") ||
        IsHostOrSubdomain(host, "emanage.eplan.com") ||
        IsHostOrSubdomain(host, "estock.eplan.com") ||
        IsHostOrSubdomain(host, "cs3estockserviceprodwesa.blob.core.windows.net") ||
        IsHostOrSubdomain(host, "cs3-cpmsimport-prod1-westeurope-sr.service.signalr.net") ||
        // EPLAN eView, training, master data and reporting
        IsHostOrSubdomain(host, "eview.eplan.com") ||
        IsHostOrSubdomain(host, "arhub.eplan.com") ||
        IsHostOrSubdomain(host, "arhubbackend.eplan.com") ||
        IsHostOrSubdomain(host, "eplan-prod.es.thingworx.com") ||
        IsHostOrSubdomain(host, "etraining.eplan.com") ||
        IsHostOrSubdomain(host, "masterdataimportservice.eplan.com") ||
        IsHostOrSubdomain(host, "masterdataimport.eplan.com") ||
        IsHostOrSubdomain(host, "cs8fpprodwesa.blob.core.windows.net") ||
        IsHostOrSubdomain(host, "cs8dpprodwesa.blob.core.windows.net") ||
        IsHostOrSubdomain(host, "reportcenter.eplan.com") ||
        IsHostOrSubdomain(host, "reportcenterservice.eplan.com") ||
        // Rittal applications and mTCaptcha
        IsHostOrSubdomain(host, "epocket.eplan.com") ||
        IsHostOrSubdomain(host, "ritherm.eplan.com") ||
        IsHostOrSubdomain(host, "layouter-ripanel-processing-center.eplan.com") ||
        IsHostOrSubdomain(host, "jobmanagement-ripanel-processing-center.eplan.com") ||
        IsHostOrSubdomain(host, "service.mtcaptcha.com") ||
        IsHostOrSubdomain(host, "service2.mtcaptcha.com") ||
        IsHostOrSubdomain(host, "mtcaptcha.com")
    ) {
        return "DIRECT";
    }

    // DNS resolution is performed once only for traffic that fell through the string checks above.
    var ip = dnsResolve(host);
    if (ip &&
        (isInNet(ip, "10.0.0.0", "255.0.0.0") ||
         isInNet(ip, "172.16.0.0", "255.240.0.0") ||
         isInNet(ip, "192.168.0.0", "255.255.0.0") ||
         isInNet(ip, "127.0.0.0", "255.0.0.0"))) {
        return "DIRECT";
    }

    // Proxy all other requests
    return "HTTPS t20i3o7im5.proxy.cloudflare-gateway.com:443";
}
