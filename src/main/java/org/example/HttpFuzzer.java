package org.example;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;

import java.io.IOException;

public class HttpFuzzer {

    private static final String USER_AGENT = "Mozilla/5.0";

    // Метод для отправки GET-запроса
    public static String sendGet(String url) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(url);

        request.addHeader("User-Agent", USER_AGENT);

        HttpResponse response = client.execute(request);
        return handleResponse(response);
    }

    // Метод для отправки POST-запроса
    public static String sendPost(String url, String payload) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost(url);

        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Content-Type", "application/json");

        request.setEntity(new StringEntity(payload));

        HttpResponse response = client.execute(request);
        return handleResponse(response);
    }

    // Метод для отправки PUT-запроса
    public static String sendPut(String url, String payload) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpPut request = new HttpPut(url);

        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Content-Type", "application/json");

        request.setEntity(new StringEntity(payload));

        HttpResponse response = client.execute(request);
        return handleResponse(response);
    }

    // Метод для отправки DELETE-запроса
    public static String sendDelete(String url) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpDelete request = new HttpDelete(url);

        request.addHeader("User-Agent", USER_AGENT);

        HttpResponse response = client.execute(request);
        return handleResponse(response);
    }

    // Обработка ответа
    private static String handleResponse(HttpResponse response) throws IOException {
        int statusCode = response.getStatusLine().getStatusCode();
        String statusDescription = response.getStatusLine().getReasonPhrase();
        return "HTTP Status Code: " + statusCode + " " + statusDescription;
    }

    // Проверка корректности URL
    public static boolean isValidUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }
}
