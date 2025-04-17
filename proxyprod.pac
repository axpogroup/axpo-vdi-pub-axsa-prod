function FindProxyForURL(url, host) {
    // No proxy for private (RFC 1918) IP addresses (intranet sites)
    if (
      isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0") ||
      isInNet(dnsResolve(host), "172.16.0.0", "255.240.0.0") ||
      isInNet(dnsResolve(host), "192.168.0.0", "255.255.0.0")
    ) {
      return "DIRECT";
    }
  
    // No proxy for localhost
    if (isInNet(dnsResolve(host), "127.0.0.0", "255.0.0.0")) {
      return "DIRECT";
    }

    // No proxy for Microsft 365 and file share and Datto
    if (
        shExpMatch(host,"*.microsoft.com") ||
        shExpMatch(host,"*.msftidentity.com") ||
        shExpMatch(host,"*.msidentity.com") ||
        shExpMatch(host,"*.windowsazure.com") ||
        shExpMatch(host,"*.windows.net") ||
        shExpMatch(host,"*.microsoftonline.com") ||
        shExpMatch(host,"*.microsoftazuread-sso.com") ||
        shExpMatch(host,"*.microsoftonline-p.net") ||
        shExpMatch(host,"*.microsoftonline-p.com") ||
        shExpMatch(host,"*.aspnetcdn.com") ||
        shExpMatch(host,"*.live.net") ||
        shExpMatch(host,"*.live.com") ||
        shExpMatch(host,"*.onedrive.com") ||
        shExpMatch(host,"*.onenote.net") ||
        shExpMatch(host,"*.onenote.com") ||
        shExpMatch(host,"*.office.net") ||
        shExpMatch(host,"*.office.com") ||
        shExpMatch(host,"*.azureedge.net") ||
        shExpMatch(host,"*.azure.net") ||
        shExpMatch(host,"*.microsoftstream.com") ||
        shExpMatch(host,"*.msauth.net") ||
        shExpMatch(host,"*.msauthimages.net") ||
        shExpMatch(host,"*.msecnd.net") ||
        shExpMatch(host,"*.msftauth.net") ||
        shExpMatch(host,"*.msftauthimages.net") ||
        shExpMatch(host,"*.phonefactor.net") ||
        shExpMatch(host,"*.cloudappsecurity.com") ||
        shExpMatch(host,"*.oaspapps.com") ||
        shExpMatch(host,"*.akadns.net") ||
        shExpMatch(host,"*.o365weve.com") ||
        shExpMatch(host,"*.onestore.ms") ||
        shExpMatch(host,"*.gfx.ms") ||
        shExpMatch(host,"*.msocdn.com") ||
        shExpMatch(host,"*.office365.com") ||
        shExpMatch(host,"*.aadrm.com") ||
        shExpMatch(host,"*.azurerms.com") ||
        shExpMatch(host,"*.azure.com") ||
        shExpMatch(host,"*.sharepointonline.com") ||
        shExpMatch(host,"*.visualstudio.com") ||
        shExpMatch(host,"*.staffhub.ms") ||
        shExpMatch(host,"*.edgesuite.net") ||
        shExpMatch(host,"*.acompli.net") ||
        shExpMatch(host,"*.outlookmobile.com") ||
        shExpMatch(host,"*.windows-ppe.net") ||
        shExpMatch(host,"*.getmicrosoftkey.com") ||
        shExpMatch(host,"*.yammer.com") ||
        shExpMatch(host,"*.yammerusercontent.com") ||
        shExpMatch(host,"*.assets-yammer.com") ||
        shExpMatch(host,"*.outlook.com") ||
        shExpMatch(host,"*.sway-cdn.com") ||
        shExpMatch(host,"*.sway-extensions.com") ||
        shExpMatch(host,"*.sway.com") ||
        shExpMatch(host,"*.entrust.net") ||
        shExpMatch(host,"*.geotrust.com") ||
        shExpMatch(host,"*.omniroot.com") ||
        shExpMatch(host,"*.public-trust.com") ||
        shExpMatch(host,"*.symcb.com") ||
        shExpMatch(host,"*.symcd.com") ||
        shExpMatch(host,"*.verisign.com") ||
        shExpMatch(host,"*.verisign.net") ||
        shExpMatch(host,"*.identrust.com") ||
        shExpMatch(host,"*.digicert.com") ||
        shExpMatch(host,"*.letsencrypt.org") ||
        shExpMatch(host,"*.globalsign.com") ||
        shExpMatch(host,"*.globalsign.net") ||
        shExpMatch(host,"*.msocsp.com") ||
        shExpMatch(host,"*.microsoft365.com") ||
        shExpMatch(host,"*.microsoftusercontent.com") ||
        shExpMatch(host,"*.azure-apim.net") ||
        shExpMatch(host,"*.powerapps.com") ||
        shExpMatch(host,"*.powerautomate.com") ||
        shExpMatch(host,"*.windows.com") ||
        shExpMatch(host,"*.cortana.ai") ||
        shExpMatch(host,"*.cloud.microsoft") ||
        shExpMatch(host,"*.static.microsoft") ||
        shExpMatch(host,"*.usercontent.microsoft") ||
        shExpMatch(host,"*.file.core.windows.net") ||
        shExpMatch(host,"*.rmm.datto.com") ||
        shExpMatch(host,"*.centralstage.net")
    ) {
    return "DIRECT";
    }

    // No proxy for Teams Communications
    if (
        //Teams Communications
        shExpMatch(host, "*.lync.com") ||
        shExpMatch(host, "*.teams.microsoft.com") ||
        shExpMatch(host, "teams.microsoft.com") ||
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

    // Proxy all other requests
    return "HTTPS t20i3o7im5.proxy.cloudflare-gateway.com:443";
}
