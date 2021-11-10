module CVE_2021_42292;

redef enum Notice::Type += {
    CVE_2021_42292,
    };

redef record HTTP::Info += {
    CVE_2021_42292_stage1_ua: bool &default=F;
    CVE_2021_42292_stage2_mime: string &default="";
    CVE_2021_42292_whitelist: bool &default=F;
    };

global CVE_2021_42292_excel_UA_pattern : pattern = /^(Microsoft Office.*Excel.*|Mozilla.*ms-office.*)/;
global CVE_2021_42292_excel_mime_pattern: pattern = /^(application\/vnd\.openxmlformats-officedocument\.spreadsheetml\.sheet|application\/vnd\.ms-excel).*/;
global CVE_2021_42292_excel_sharepoint_string: string = "MICROSOFTSHAREPOINTTEAMSERVICES";

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if (is_orig) 
        {
        # No need to look at any more client headers if the connection has already been flagged as a candidate
        if (c$http$CVE_2021_42292_stage1_ua)
            return;
        # Look for the Excel UA pattern in client headers
        if (name == "USER-AGENT" && CVE_2021_42292_excel_UA_pattern in value)
            {
            c$http$CVE_2021_42292_stage1_ua = T;
            return;
            }
        }

    # If Server header and we haven't already seen the excel UA from preceding client headers, 
    # OR this connection has been whitelisted already, return.
    if (!c$http$CVE_2021_42292_stage1_ua || c$http$CVE_2021_42292_whitelist)
        return;
    
    # Check if the Server Content-Type matches Excel 
    if (name == "CONTENT-TYPE" && CVE_2021_42292_excel_mime_pattern in value)
        {
        c$http$CVE_2021_42292_stage2_mime = value;
        return;
        }
    # Flag benign traffic that would otherwise raise a notice
    if (name == CVE_2021_42292_excel_sharepoint_string)
        c$http$CVE_2021_42292_whitelist = T;
    }

event http_end_entity(c: connection, is_orig: bool)
    {
    if (|c$http$CVE_2021_42292_stage2_mime| > 0 && !c$http$CVE_2021_42292_whitelist)
        {
        NOTICE([$note=CVE_2021_42292,
            $conn=c,
            $msg=fmt("%s may be compromised by CVE-2021-42292, MS Office Excel download using Office from %s detected. See sub field for additional triage information", c$id$orig_h, c$id$orig_h),
            $sub=fmt("host='%s', method='%s', user_agent='%s', CONTENT-TYPE='%s', uri='%s'", c$http$host, c$http$method, c$http$user_agent, c$http$CVE_2021_42292_stage2_mime, c$http$uri),
            $identifier=cat(c$id$orig_h,c$id$resp_p,c$http$CVE_2021_42292_stage2_mime,c$http$method,c$http$user_agent,c$http$uri)]);
        }
    }
