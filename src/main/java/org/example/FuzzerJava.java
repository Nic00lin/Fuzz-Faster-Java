package org.example;

import javafx.application.Application;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.Separator;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox();
        root.setSpacing(10);
        root.setAlignment(Pos.TOP_CENTER);
        root.getStyleClass().add("root");

        // Информация
        Label appInfoLabel = new Label("Fuzzer - это инструмент для тестирования, позволяющий найти уязвимости в веб-приложениях");
        appInfoLabel.setWrapText(true);
        appInfoLabel.getStyleClass().add("label-background");

        // Контейнер для поля ввода и кнопки проверки доступности
        HBox inputBox = new HBox();
        inputBox.setSpacing(10);
        inputBox.setAlignment(Pos.CENTER);
        inputBox.getStyleClass().add("input-box");

        // URL
        TextField urlTextField = new TextField();
        urlTextField.setPromptText("Введите URL адрес");
        urlTextField.getStyleClass().add("text-field");

        Button checkAvailabilityButton = new Button("Проверить доступность");
        checkAvailabilityButton.setMinWidth(180);
        checkAvailabilityButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки проверки доступности
        checkAvailabilityButton.setOnAction(event -> {
            String url = urlTextField.getText();
            String statusCode = Fuzzer.sendRequest(url);
            if (statusCode.equals("Неверно введен URL")) {
                displayError(statusCode);
            } else {
                displayResponse(statusCode);
            }
        });

        // Полоса с надписью "Методы фаззинга"
        HBox separatorBox = new HBox();
        separatorBox.setAlignment(Pos.CENTER);
        separatorBox.setSpacing(10);
        separatorBox.setPrefWidth(638);

        Separator leftSeparator = new Separator();
        Label fuzzingMethodsLabel = new Label("Методы фаззинга");
        fuzzingMethodsLabel.setStyle("-fx-font-size: 16px; -fx-text-fill: white;");
        Separator rightSeparator = new Separator();

        separatorBox.getChildren().addAll(leftSeparator, fuzzingMethodsLabel, rightSeparator);
        HBox.setHgrow(leftSeparator, Priority.ALWAYS);
        HBox.setHgrow(rightSeparator, Priority.ALWAYS);

        // Контейнер для поля ввода и кнопки фаззинга
        VBox fuzzingBox = new VBox();
        fuzzingBox.setSpacing(10);
        fuzzingBox.setAlignment(Pos.CENTER);
        fuzzingBox.getStyleClass().add("fuzzing-box");

        Button startFuzzingButton = new Button("Начать Http фаззинг");
        startFuzzingButton.setMinWidth(220);
        startFuzzingButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки фаззинга
        startFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                StringBuilder responses = new StringBuilder();
                responses.append("GET: ").append(HttpFuzzer.sendGet(url)).append("\n");
                responses.append("POST: ").append(HttpFuzzer.sendPost(url, "{\"name\":\"test\"}")).append("\n");
                responses.append("PUT: ").append(HttpFuzzer.sendPut(url, "{\"name\":\"test\"}")).append("\n");
                responses.append("DELETE: ").append(HttpFuzzer.sendDelete(url)).append("\n");
                displayAllResponses(responses.toString());
            } catch (IOException e) {
                displayError("Ошибка при выполнении запросов: " + e.getMessage());
            }
        });

        // Контейнер для кнопки фаззинга заголовков
        Button startHeaderFuzzingButton = new Button("Начать фаззинг заголовков");
        startHeaderFuzzingButton.setMinWidth(220);
        startHeaderFuzzingButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки фаззинга заголовков
        startHeaderFuzzingButton.setOnAction(event -> {
            String url = urlTextField.getText();
            if (!HttpFuzzer.isValidUrl(url)) {
                displayError("Неверно введен URL");
                return;
            }

            try {
                Map<String, String> headers = HeaderFuzzer.generateHeaders();
                String response = HeaderFuzzer.sendGetWithHeaders(url, headers);
                displayAllResponses("GET с заголовками: " + response);
            } catch (IOException e) {
                displayError("Ошибка при выполнении запросов: " + e.getMessage());
            }
        });

        inputBox.getChildren().addAll(urlTextField, checkAvailabilityButton);
        fuzzingBox.getChildren().addAll(separatorBox, startFuzzingButton, startHeaderFuzzingButton);

        root.getChildren().addAll(appInfoLabel, inputBox, fuzzingBox);

        Scene scene = new Scene(root, 638, 600);
        scene.getStylesheets().add(getClass().getResource("/styles.css").toExternalForm());

        primaryStage.setTitle("FuzzerJava");
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("/icon.jpg")));
        primaryStage.setScene(scene);
        primaryStage.show();
    }

    private void displayResponse(String response) {
        Stage responseStage = new Stage();
        responseStage.setTitle("HTTP Response");

        HBox root = new HBox();
        root.setAlignment(Pos.CENTER_LEFT);
        root.setSpacing(10);
        root.setStyle("-fx-padding: 10;");

        ImageView icon = new ImageView(new Image(getClass().getResourceAsStream("/ok-icon.png")));
        icon.setFitWidth(48);
        icon.setFitHeight(48);

        Label responseLabel = new Label(response);
        responseLabel.setStyle("-fx-font-size: 16px;");
        responseLabel.setWrapText(true);

        root.getChildren().addAll(icon, responseLabel);

        Scene scene = new Scene(root, 400, 200);
        responseStage.setScene(scene);
        responseStage.show();
    }

    private void displayError(String errorMessage) {
        Stage errorStage = new Stage();
        errorStage.setTitle("Ошибка");

        HBox root = new HBox();
        root.setAlignment(Pos.CENTER_LEFT);
        root.setSpacing(10);
        root.setStyle("-fx-padding: 10;");

        ImageView icon = new ImageView(new Image(getClass().getResourceAsStream("/error-icon.png")));
        icon.setFitWidth(48);
        icon.setFitHeight(48);

        Label errorLabel = new Label(errorMessage);
        errorLabel.setStyle("-fx-font-size: 16px;");
        errorLabel.setWrapText(true);

        root.getChildren().addAll(icon, errorLabel);

        Scene scene = new Scene(root, 400, 200);
        errorStage.setScene(scene);
        errorStage.show();
    }

    private void displayAllResponses(String responses) {
        Stage responseStage = new Stage();
        responseStage.setTitle("HTTP Responses");

        VBox root = new VBox();
        root.setAlignment(Pos.CENTER_LEFT);
        root.setSpacing(10);
        root.setStyle("-fx-padding: 10;");

        ImageView icon = new ImageView(new Image(getClass().getResourceAsStream("/ok-icon.png")));
        icon.setFitWidth(48);
        icon.setFitHeight(48);

        TextArea responseArea = new TextArea(responses);
        responseArea.setStyle("-fx-font-size: 16px;");
        responseArea.setWrapText(true);
        responseArea.setEditable(false);

        root.getChildren().addAll(icon, responseArea);

        Scene scene = new Scene(root, 400, 400);
        responseStage.setScene(scene);
        responseStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
