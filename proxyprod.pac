function FindProxyForURL(url, host) {

    // ── 1. CHEAPEST CHECKS — no DNS, no pattern matching ─────────────────────
    if (
        isPlainHostName(host) ||
        host == "localhost"   ||
        host == "127.0.0.1"
    ) {
        return "DIRECT";
    }

    // ── 2. EPLAN PLATFORM, SERVICES & RITTAL APPLICATIONS ────────────────────
    if (
        // Core / Identity / Auth
        shExpMatch(host, "*.goto.eplan.com")                                ||
        shExpMatch(host, "*.identityservice.eplan.com")                     ||
        shExpMatch(host, "*.legalnotes.eplan.com")                          ||
        shExpMatch(host, "*.login.eplan.com")                               ||
        shExpMatch(host, "*.myaccountservice.eplan.com")                    ||
        shExpMatch(host, "*.mysettings.eplan.com")                          ||
        shExpMatch(host, "*.selfservice.eplan.com")                         ||
        shExpMatch(host, "*.useradministration.eplan.com")                  ||
        shExpMatch(host, "*.www.eplan.com")                                 ||
        shExpMatch(host, "*.www.eplan.help")                                ||
        // Platform Services
        shExpMatch(host, "*.api.eplan.com")                                 ||
        shExpMatch(host, "*.apps.eplan.com")                                ||
        shExpMatch(host, "*.appsservice.eplan.com")                         ||
        shExpMatch(host, "*.configuration.eplan.com")                       ||
        shExpMatch(host, "*.fileprovider.eplan.com")                        ||
        shExpMatch(host, "*.licensingservice.eplan.com")                    ||
        shExpMatch(host, "*.licensingservicev5.eplan.com")                  ||
        shExpMatch(host, "*.mgmtservice.eplan.com")                         ||
        shExpMatch(host, "*.notificationservice.eplan.com")                 ||
        // Data Portal
        shExpMatch(host, "*.dataportal.eplan.com")                          ||
        // eBuild
        shExpMatch(host, "*.ebuilddesigner.eplan.com")                      ||
        shExpMatch(host, "*.ebuildprojectbuilder.eplan.com")                ||
        // eManage
        shExpMatch(host, "*.emanage.eplan.com")                             ||
        // eStock
        shExpMatch(host, "*.cs3-cpmsimport-prod1-westeurope-sr.service.signalr.net") ||
        shExpMatch(host, "*.cs3estockserviceprodwesa.blob.core.windows.net")         ||
        shExpMatch(host, "*.estock.eplan.com")                              ||
        // eTraining (eLearning)
        shExpMatch(host, "*.etraining.eplan.com")                           ||
        // eView
        shExpMatch(host, "*.eview.eplan.com")                               ||
        // eView AR
        shExpMatch(host, "*.arhub.eplan.com")                               ||
        shExpMatch(host, "*.arhubbackend.eplan.com")                        ||
        shExpMatch(host, "*.eplan-prod.es.thingworx.com")                   ||
        // Master Data Import
        shExpMatch(host, "*.cs8dpprodwesa.blob.core.windows.net")           ||
        shExpMatch(host, "*.cs8fpprodwesa.blob.core.windows.net")           ||
        shExpMatch(host, "*.masterdataimport.eplan.com")                    ||
        shExpMatch(host, "*.masterdataimportservice.eplan.com")             ||
        // Report Center
        shExpMatch(host, "*.reportcenter.eplan.com")                        ||
        shExpMatch(host, "*.reportcenterservice.eplan.com")                 ||
        // Rittal ePocket
        shExpMatch(host, "*.epocket.eplan.com")                             ||
        // Rittal RiPanel Processing Center
        shExpMatch(host, "*.jobmanagement-ripanel-processing-center.eplan.com") ||
        shExpMatch(host, "*.layouter-ripanel-processing-center.eplan.com")      ||
        // Rittal RiTherm
        shExpMatch(host, "*.ritherm.eplan.com")                             ||
        // mTCaptcha (used by Eplan)
        shExpMatch(host, "*.mtcaptcha.com")                                 ||
        shExpMatch(host, "*.service.mtcaptcha.com")                         ||
        shExpMatch(host, "*.service2.mtcaptcha.com")
    ) {
        return "DIRECT";
    }

    // ── 3. MICROSOFT — Identity & Authentication ──────────────────────────────
    if (
        shExpMatch(host, "*.microsoftazuread-sso.com") ||
        shExpMatch(host, "*.microsoftonline-p.com")    ||
        shExpMatch(host, "*.microsoftonline-p.net")    ||
        shExpMatch(host, "*.microsoftonline.com")      ||
        shExpMatch(host, "*.msauth.net")               ||
        shExpMatch(host, "*.msauthimages.net")         ||
        shExpMatch(host, "*.msftauth.net")             ||
        shExpMatch(host, "*.msftauthimages.net")       ||
        shExpMatch(host, "*.msftidentity.com")         ||
        shExpMatch(host, "*.msidentity.com")           ||
        shExpMatch(host, "*.phonefactor.net")
    ) {
        return "DIRECT";
    }

    // ── 4. MICROSOFT — Office 365 & Core Services ────────────────────────────
    if (
        shExpMatch(host, "*.cloud.microsoft")          ||
        shExpMatch(host, "*.microsoft.com")            ||
        shExpMatch(host, "*.microsoft365.com")         ||
        shExpMatch(host, "*.microsoftstream.com")      ||
        shExpMatch(host, "*.microsoftusercontent.com") ||
        shExpMatch(host, "*.office.com")               ||
        shExpMatch(host, "*.office.net")               ||
        shExpMatch(host, "*.office365.com")            ||
        shExpMatch(host, "*.onedrive.com")             ||
        shExpMatch(host, "*.onenote.com")              ||
        shExpMatch(host, "*.outlook.com")              ||
        shExpMatch(host, "*.sharepointonline.com")     ||
        shExpMatch(host, "*.static.microsoft")         ||
        shExpMatch(host, "*.usercontent.microsoft")
    ) {
        return "DIRECT";
    }

    // ── 5. MICROSOFT — Azure Platform ────────────────────────────────────────
    if (
        shExpMatch(host, "*.azure-apim.net")           ||
        shExpMatch(host, "*.azure.com")                ||
        shExpMatch(host, "*.azure.net")                ||
        shExpMatch(host, "*.azureedge.net")            ||
        shExpMatch(host, "*.azurerms.com")             ||
        shExpMatch(host, "*.file.core.windows.net")    ||
        shExpMatch(host, "*.windows-ppe.net")          ||
        shExpMatch(host, "*.windows.com")              ||
        shExpMatch(host, "*.windows.net")              ||
        shExpMatch(host, "*.windowsazure.com")
    ) {
        return "DIRECT";
    }

    // ── 6. MICROSOFT — Power Platform & Productivity ─────────────────────────
    if (
        shExpMatch(host, "*api.powerbi.com")           ||
        shExpMatch(host, "*.cortana.ai")               ||
        shExpMatch(host, "*.powerapps.com")            ||
        shExpMatch(host, "*.powerautomate.com")        ||
        shExpMatch(host, "*.sway-cdn.com")             ||
        shExpMatch(host, "*.sway-extensions.com")      ||
        shExpMatch(host, "*.sway.com")
    ) {
        return "DIRECT";
    }

    // ── 7. MICROSOFT — CDN, Edge & Miscellaneous ─────────────────────────────
    if (
        shExpMatch(host, "*.acompli.net")              ||
        shExpMatch(host, "*.akadns.net")               ||
        shExpMatch(host, "*.aspnetcdn.com")            ||
        shExpMatch(host, "*.assets-yammer.com")        ||
        shExpMatch(host, "*.cloudappsecurity.com")     ||
        shExpMatch(host, "*.edgesuite.net")            ||
        shExpMatch(host, "*.getmicrosoftkey.com")      ||
        shExpMatch(host, "*.gfx.ms")                   ||
        shExpMatch(host, "*.live.com")                 ||
        shExpMatch(host, "*.live.net")                 ||
        shExpMatch(host, "*.msocdn.com")               ||
        shExpMatch(host, "*.msecnd.net")               ||
        shExpMatch(host, "*.o365weve.com")             ||
        shExpMatch(host, "*.oaspapps.com")             ||
        shExpMatch(host, "*.onestore.ms")              ||
        shExpMatch(host, "*.outlookmobile.com")        ||
        shExpMatch(host, "*.staffhub.ms")              ||
        shExpMatch(host, "*.yammer.com")               ||
        shExpMatch(host, "*.yammerusercontent.com")
    ) {
        return "DIRECT";
    }

    // ── 8. CERTIFICATE AUTHORITIES ────────────────────────────────────────────
    if (
        shExpMatch(host, "*.aadrm.com")                ||
        shExpMatch(host, "*.digicert.com")             ||
        shExpMatch(host, "*.entrust.net")              ||
        shExpMatch(host, "*.geotrust.com")             ||
        shExpMatch(host, "*.globalsign.com")           ||
        shExpMatch(host, "*.globalsign.net")           ||
        shExpMatch(host, "*.identrust.com")            ||
        shExpMatch(host, "*.letsencrypt.org")          ||
        shExpMatch(host, "*.msocsp.com")               ||
        shExpMatch(host, "*.omniroot.com")             ||
        shExpMatch(host, "*.public-trust.com")         ||
        shExpMatch(host, "*.symcb.com")                ||
        shExpMatch(host, "*.symcd.com")                ||
        shExpMatch(host, "*.verisign.com")             ||
        shExpMatch(host, "*.verisign.net")
    ) {
        return "DIRECT";
    }

    // ── 9. MICROSOFT TEAMS & SKYPE COMMUNICATIONS ────────────────────────────
    if (
        shExpMatch(host, "adl.windows.com")                         ||
        shExpMatch(host, "aka.ms")                                  ||
        shExpMatch(host, "compass-ssl.microsoft.com")               ||
        shExpMatch(host, "mlccdn.blob.core.windows.net")            ||
        shExpMatch(host, "teams.microsoft.com")                     ||
        shExpMatch(host, "*.keydelivery.mediaservices.windows.net") ||
        shExpMatch(host, "*.lync.com")                              ||
        shExpMatch(host, "*.secure.skypeassets.com")                ||
        shExpMatch(host, "*.skype.com")                             ||
        shExpMatch(host, "*.streaming.mediaservices.windows.net")   ||
        shExpMatch(host, "*.teams.microsoft.com")                   ||
        shExpMatch(host, "*.users.storage.live.com")
    ) {
        return "DIRECT";
    }

    // ── 10. THIRD-PARTY & PARTNER APPLICATIONS ───────────────────────────────
    if (
        shExpMatch(host, "*.centralstage.net")              ||  // Datto
        shExpMatch(host, "*.rmm.datto.com")                 ||  // Datto RMM
        shExpMatch(host, "*.tcft.ch")                       ||  // TCFT
        shExpMatch(host, "planta-ppm-backend.axpo.app")         // Axpo Planta PPM
        // addresses to add once approved:
        // shExpMatch(host, "argocd-iamapial-pub.axpo.cloud/applications")      ||
        // shExpMatch(host, "argocd-test-iamapial-pub.axpo.cloud/applications") ||
        // shExpMatch(host, "argocd-dev-iamapial-pub.axpo.cloud/applications")
    ) {
        return "DIRECT";
    }

    // ── 11. PRIVATE IP RANGES — DNS resolved ONCE, only for remaining traffic ─
    var ip = dnsResolve(host);
    if (ip &&
        (isInNet(ip, "10.0.0.0",    "255.0.0.0")  ||
         isInNet(ip, "172.16.0.0",  "255.240.0.0") ||
         isInNet(ip, "192.168.0.0", "255.255.0.0") ||
         isInNet(ip, "127.0.0.0",   "255.0.0.0"))) {
        return "DIRECT";
    }

    // ── 12. PROXY all remaining traffic ──────────────────────────────────────
    return "HTTPS t20i3o7im5.proxy.cloudflare-gateway.com:443";
}
