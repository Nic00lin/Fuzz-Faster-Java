package org.example;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClientBuilder;
import java.io.IOException;

public class Fuzzer {
    public static String sendRequest(String url) {
        // Проверка на корректность URL
        if (!isValidUrl(url)) {
            return "Неверно введен URL";
        }

        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(url);

        try {
            HttpResponse response = client.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            String statusDescription = response.getStatusLine().getReasonPhrase();
            return "HTTP Status Code: " + statusCode + " " + statusDescription;

        } catch (IOException e) {
            e.printStackTrace();
            return "Ошибка при выполнении запроса: " + e.getMessage();
        }
    }

    private static boolean isValidUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }
}
