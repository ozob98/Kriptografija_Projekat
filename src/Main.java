import menu.Menu;
import registrationlogin.Login;
import registrationlogin.Registration;
import user.UserFile;
import user.UserFileService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.InputMismatchException;
import java.util.Objects;
import java.util.Scanner;


public class Main {

    private static Scanner scanner = new Scanner(System.in);
    private static Registration registration = new Registration();
    private static Login login = new Login();
    private static UserFileService userFileService = new UserFileService();

    public static void main(String[] args) {
        boolean quit = false;
        Menu.showMainMenu();

        while (!quit) {
            try {
                int action = scanner.nextInt();
                scanner.nextLine();
                if (action >= 1 && action <= 3) {
                    switch (action) {
                        case 1 -> {
                            login.loginUser();
                            goToUserAccount();
                            login.restoreLogin();
                        }
                        case 2 -> {
                            Menu.showRegistrationMenu();
                            registration.registerUser();
                            Menu.showMainMenu();
                        }
                        case 3 -> {
                            quit = true;
                            System.out.println("Exiting...");
                        }
                    }
                } else {
                    System.out.println("Enter a number from 1-3");
                }
            } catch (InputMismatchException e) {
                System.out.println("Invalid input! Must enter only integers.");
                scanner.nextLine();
                Menu.showMainMenu();
            } catch (Exception e) {
                e.printStackTrace();
                Menu.showMainMenu();
            }
        }
    }

    private static void goToUserAccount() {
        while (login.logged) {
            try {
                Menu.showUserMenu();
                int action = scanner.nextInt();
                scanner.nextLine();
                switch (action) {
                    case 1 -> {
                        System.out.println(login.loggedUser);
                    }
                    case 2 -> {
                        System.out.println("Files you have in your repository: ");
                        UserFileService.listFiles(login.loggedUser);
                    }
                    case 3 -> {
                        System.out.println("Locate your file, copy and paste here the file path:");
                        UserFile userFile;
                        userFile = userFileService.readUserFile();
                        if (!Objects.isNull(userFile)) {
                            UserFileService.uploadFile(login.loggedUser, userFile);
                            System.out.println("File uploaded.");
                        }
                    }
                    case 4 -> {
                        System.out.println("Files in this repository: ");
                        if(UserFileService.listFiles(login.loggedUser)) {
                            System.out.println("Enter the name of file you want to retrieve: ");
                            String fileName = scanner.nextLine();
                            byte[] retrievedFile = UserFileService.getFile(login.loggedUser, fileName);
                            if (!Objects.isNull(retrievedFile)) {
                                Path path = Paths.get(fileName);
                                Files.write(path, retrievedFile);
                            }
                        }
                    }
                    case 5 -> {
                        System.out.println("Logout...");
                        login.logged = false;
                        login.loggedUser.setUserToNull();
                        login.restoreLogin();
                        Menu.showMainMenu();
                    }
                }
            } catch (InputMismatchException e) {
                System.out.println("Invalid input! Must enter only integers.");
                scanner.nextLine();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }
}