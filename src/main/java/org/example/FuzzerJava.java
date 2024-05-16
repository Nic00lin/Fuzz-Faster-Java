package org.example;

import javafx.application.Application;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        VBox root = new VBox();
        root.setSpacing(10);
        root.setAlignment(Pos.TOP_CENTER); // Центрирование содержимого по горизонтали
        root.getStyleClass().add("root");

        // Информация
        Label appInfoLabel = new Label("Fuzzer - это инструмент для тестирования, позволяющий найти уязвимости в веб-приложениях");
        appInfoLabel.setWrapText(true);
        appInfoLabel.getStyleClass().add("label-background");

        // Контейнер для поля ввода и кнопки
        HBox inputBox = new HBox();
        inputBox.setSpacing(10);
        inputBox.setAlignment(Pos.CENTER);
        inputBox.getStyleClass().add("input-box");

        // URL
        TextField urlTextField = new TextField();
        urlTextField.setPromptText("Введите URL адрес");
        urlTextField.getStyleClass().add("text-field");

        Button checkAvailabilityButton = new Button("Проверить доступность");
        checkAvailabilityButton.setMinWidth(165);
        checkAvailabilityButton.getStyleClass().add("button");

        // Устанавливаем обработчик событий для кнопки
        checkAvailabilityButton.setOnAction(event -> {
            String url = urlTextField.getText();
            String statusCode = Fuzzer.sendRequest(url);
            if (statusCode.equals("Неверно введен URL")) {
                displayError(statusCode);
            } else {
                displayResponse(statusCode);
            }
        });

        inputBox.getChildren().addAll(urlTextField, checkAvailabilityButton);
        root.getChildren().addAll(appInfoLabel, inputBox);

        Scene scene = new Scene(root, 685, 600);
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

        // Проверяем, если ответ содержит код 200 OK
        if (response.contains("HTTP Status Code: 200 OK")) {
            ImageView icon = new ImageView(new Image(getClass().getResourceAsStream("/ok-icon.png")));
            icon.setFitWidth(48);
            icon.setFitHeight(48);

            Label responseLabel = new Label("Ответ сервера: HTTP 200 OK");
            responseLabel.setStyle("-fx-font-size: 16px;");
            responseLabel.setWrapText(true);

            root.getChildren().addAll(icon, responseLabel);
        } else {
            Label responseLabel = new Label(response);
            responseLabel.setStyle("-fx-font-size: 16px;");
            responseLabel.setWrapText(true);
            root.getChildren().add(responseLabel);
        }

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
        errorLabel.setStyle("-fx-text-fill: red; -fx-font-size: 16px;");
        errorLabel.setWrapText(true);

        root.getChildren().addAll(icon, errorLabel);

        Scene scene = new Scene(root, 300, 200);
        errorStage.setScene(scene);
        errorStage.showAndWait();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
