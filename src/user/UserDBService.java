package user;

import java.io.*;
import java.util.ArrayList;

public class UserDBService {
    private static final String USERS_FILE = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\usersDB\\users.txt";

    public static void writeUser(User user) throws Exception {
        try{
            BufferedWriter writer = new BufferedWriter(new FileWriter(USERS_FILE,true));
            writer.write(user.getUsername() + "," + user.getPassword() + "," + user.getName() + "," + user.getLastname() + "," + user.getEmail() + "," + user.getPhone());
            writer.newLine();
            writer.close();
        }catch(IOException e){
           throw new Exception("Error while saving user's data in DB",e);
        }
    }

    public static ArrayList<User> readUsers(){
        ArrayList<User> users = new ArrayList<>();
        try{
            BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE));
            String line;
            while((line = reader.readLine()) != null){
                String[] userData = line.split(",");
                User user = new User(userData[0], userData[1], userData[2], userData[3], userData[4], userData[5] );
                users.add(user);
            }
            reader.close();
        }catch(Exception e){
            e.printStackTrace();
        }
        return users;
    }

    public static User getUser(String username){
        User users = new User();
        try{
            BufferedReader reader = new BufferedReader(new FileReader(USERS_FILE));
            String line;
            while((line = reader.readLine()) != null){
                String[] userData = line.split(",");
                User user = new User(userData[0], userData[1], userData[2], userData[3], userData[4], userData[5] );
                if(user.getUsername().equals(username)) {
                    users = user;
                    break;
                }
            }
            reader.close();
        }catch(Exception e){
            e.printStackTrace();
        }
        return users;
    }

    public static boolean userExists(String username) {
        ArrayList<User> users = readUsers();
        for (User user : users) {
            if (user.getUsername().equals(username)) {
                return true;
            }
        }
        return false;
    }

}
