package org.example;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.*;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.protocol.HTTP;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class HeaderFuzzer {

    private static final String USER_AGENT = "Mozilla/5.0";

    // Метод для отправки GET-запроса с заголовками
    public static String sendGetWithHeaders(String url, Map<String, String> headers) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(url);

        request.addHeader("User-Agent", USER_AGENT);
        headers.forEach(request::addHeader);

        HttpResponse response = client.execute(request);
        return handleResponse(response, headers);
    }

    // Метод для отправки POST-запроса с заголовками
    public static String sendPostWithHeaders(String url, Map<String, String> headers, String body) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpPost request = new HttpPost(url);

        request.addHeader("User-Agent", USER_AGENT);
        headers.forEach(request::addHeader);
        request.setEntity(new StringEntity(body));

        HttpResponse response = client.execute(request);
        return handleResponse(response, headers);
    }

    // Метод для отправки PUT-запроса с заголовками
    public static String sendPutWithHeaders(String url, Map<String, String> headers, String body) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpPut request = new HttpPut(url);

        request.addHeader("User-Agent", USER_AGENT);
        headers.forEach(request::addHeader);
        request.setEntity(new StringEntity(body));

        HttpResponse response = client.execute(request);
        return handleResponse(response, headers);
    }

    // Метод для отправки DELETE-запроса с заголовками
    public static String sendDeleteWithHeaders(String url, Map<String, String> headers) throws IOException {
        HttpClient client = HttpClientBuilder.create().build();
        HttpDelete request = new HttpDelete(url);

        request.addHeader("User-Agent", USER_AGENT);
        headers.forEach(request::addHeader);

        HttpResponse response = client.execute(request);
        return handleResponse(response, headers);
    }

    // Обработка ответа
    private static String handleResponse(HttpResponse response, Map<String, String> headers) throws IOException {
        int statusCode = response.getStatusLine().getStatusCode();
        String statusDescription = response.getStatusLine().getReasonPhrase();
        StringBuilder headerInfo = new StringBuilder();
        headers.forEach((key, value) -> headerInfo.append(key).append(": ").append(value).append("\n"));
        return "HTTP Status Code: " + statusCode + " " + statusDescription + "\n\nИспользованные заголовки:\n" + headerInfo.toString();
    }

    // Генерация заголовков для фаззинга
    public static Map<String, String> generateHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP.USER_AGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3");
        headers.put("X-Forwarded-For", "127.0.0.1");
        headers.put("Referer", "http://example.com");
        headers.put("Authorization", "Bearer some_token");
        headers.put("X-Requested-With", "XMLHttpRequest");
        return headers;
    }

    public static void main(String[] args) {
        String url = "http://example.com";
        Map<String, String> headers = generateHeaders();
        String body = "{\"name\":\"test\"}";
        try {
            System.out.println("GET с заголовками: " + sendGetWithHeaders(url, headers));
            System.out.println("POST с заголовками: " + sendPostWithHeaders(url, headers, body));
            System.out.println("PUT с заголовками: " + sendPutWithHeaders(url, headers, body));
            System.out.println("DELETE с заголовками: " + sendDeleteWithHeaders(url, headers));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
