# axpo-vdi-pub-axsa-prod

## Overview
This repository contains the Proxy Auto-Configuration (PAC) files used for managing internet traffic routing on **Azure Virtual Desktop (AVD) Multisession** environments at Axpo.

The PAC files define which URLs and domains are accessed **directly** (bypassing the proxy) and which are routed through the **Cloudflare Gateway proxy** (`t20i3o7im5.proxy.cloudflare-gateway.com:443`).

---

## Files

### `proxyprod.pac`
PAC file used in the **Production** AVD Multisession environment.  
Applied via Group Policy Object: **`GPO-UCL-AVDMulti`**

### `proxydev.pac`
PAC file used in the **Development / UAT** AVD Multisession environment.  
Applied via Group Policy Object: **`GPO-UCL-AVDMulti-Win11-UAT`**

---

## PAC File Structure

Both PAC files follow the same structure and contain bypass rules for the following categories:

| Category | Description |
|---|---|
| **Private IP Ranges** | RFC 1918 addresses (10.x, 172.16.x, 192.168.x) go direct |
| **Localhost** | 127.0.0.x goes direct |
| **Microsoft 365 & Azure** | All Microsoft cloud services, Office 365, Azure, OneDrive, SharePoint, etc. |
| **Teams Communications** | Skype, Lync, Teams media and signaling endpoints |
| **Eplan Platform & Services** | All Eplan cloud applications incl. eBuild, eStock, eView, eManage, eTraining, Data Portal, Report Center, Master Data Import |
| **Rittal Applications** | ePocket, RiTherm, RiPanel Processing Center, Job Management |
| **mTCaptcha** | Captcha service used by Eplan |
| **Datto RMM** | Remote monitoring and management |
| **Other** | Axpo-specific apps (e.g. planta-ppm-backend.axpo.app) |

All other traffic is routed through the Cloudflare Gateway proxy.

---

## Deployment

The PAC files are distributed to AVD Multisession session hosts via **Group Policy (GPO)** and configured as the proxy auto-config URL in the browser/system proxy settings.

| Environment | GPO |
|---|---|
| Production | `GPO-UCL-AVDMulti` |
| Development / UAT | `GPO-UCL-AVDMulti-Win11-UAT` |