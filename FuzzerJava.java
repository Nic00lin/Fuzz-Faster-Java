import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;
import javafx.scene.image.Image;

public class FuzzerJava extends Application {

    @Override
    public void start(Stage primaryStage) {
        StackPane root = new StackPane();

        Scene scene = new Scene(root, 800, 600);

        primaryStage.setTitle("FuzzerJava");
        primaryStage.getIcons().add(new Image(getClass().getResourceAsStream("icon.jpg")));
        primaryStage.setScene(scene);

        scene.getStylesheets().add(getClass().getResource("styles.css").toExternalForm());

        primaryStage.show();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
