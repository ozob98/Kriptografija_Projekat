package user;

import security.encryption.FileEncryption;
import validators.FilePathValidator;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

public class UserFileService {

  private static final String USERS_REPOSITORY = "C:\\Users\\ozob9\\Desktop\\FAKS\\3. god\\kriptografija\\Kriptografija_Projekat\\repositories\\";
  private FilePathValidator filePathValidator = new FilePathValidator();
  private static final Scanner SCANNER = new Scanner(System.in);


  private static String getUserFilesDirectoryPath(User user) {
    return USERS_REPOSITORY + user.getUsername() + "\\files\\";
  }

  private static String getUserFilesSignaturesPath(User user) {
    return USERS_REPOSITORY + user.getUsername() + "\\signatures\\";
  }

  private static List<String> getAllFilesNames(User user) {
    File userRepository = new File(getUserFilesDirectoryPath(user));
    if (userRepository.exists()) {
      File[] segmentDirectories = userRepository.listFiles();
      if (segmentDirectories != null && segmentDirectories.length != 0) {
        List<String> allFiles = new ArrayList<>();
        File firstSegmentDirectory = segmentDirectories[0]; //jer svaki fajl ima sigurno jedan segment
        File[] files = firstSegmentDirectory.listFiles();
        if (!Objects.isNull(files)) {
          for (File file : files) {
            allFiles.add(file.getName().substring(0, file.getName().length() - 2));
          }
          return allFiles;
        }
      }
    }
    return null;
  }

  private static byte[] getFileSignature(User user, String fileName) {

    File userSignaturesDirectory = new File(getUserFilesSignaturesPath(user));

    if (userSignaturesDirectory.exists()) {
      try {
        FilenameFilter filter = (dir, name) -> name.contains(fileName);
        File[] signatures = userSignaturesDirectory.listFiles(filter);
        if (signatures != null && signatures.length > 0) {
          byte[] signature = Files.readAllBytes(signatures[0].toPath());
          return signature;
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    return null;
  }

  private static boolean fileExists(User user, String fileName) {

    List<String> allFiles = getAllFilesNames(user);

    if (!Objects.isNull(allFiles)) {
      for (String file : allFiles) {
        if (file.equals(fileName)) {
          return true;
        }
      }
    }
    return false;
  }

  public UserFile readUserFile() {

    UserFile userFile = new UserFile();

    String filePath = "";
    do {
      System.out.println("Enter the file path: ");
      filePath = SCANNER.nextLine();
    } while (!filePathValidator.validate(filePath));

    try {
      File file = new File(filePath);
      if (file.exists()) {
        String fileName = file.getName();
        byte[] fileToEncrypt = Files.readAllBytes(Paths.get(filePath));
        //byte[] keyBytes = FileEncryption.generateKeyBytes();
        //byte[] iv = FileEncryption.generateIV();
        byte[] encryptedFile = FileEncryption.encryptFile(fileToEncrypt);
        userFile.setFile(encryptedFile);
        userFile.setFileName(fileName);
        //userFile.setFilePath(filePath);
        //userFile.setKeyBytes(keyBytes);
        //userFile.setIV(iv);
        return userFile;
      } else {
        System.out.println("File does not exist");
        return null;
      }
    } catch (IOException e) {
      System.out.println("Error while reading file");
      return null;
    }
  }

  public static void makeUserRepository(User user) throws Exception {

    Path folderPath = Paths.get(USERS_REPOSITORY + user.getUsername());
    try {
      File userRepo = new File(folderPath.toString());
      if (!userRepo.exists()) {
        Files.createDirectory(folderPath);
      }
    } catch (IOException e) {
      throw new Exception("Error while trying to create a directory", e);
    }
  }

  public static void uploadFile(User user, UserFile userFile) {

    if (fileExists(user, userFile.getFileName())) {
      System.out.println("File with the same name already exists!");
    } else {
      try {
        makeUserRepository(user);
        Path filesDirectory = Paths.get(getUserFilesDirectoryPath(user));
        if (!Files.exists(filesDirectory)) {
          Files.createDirectory(filesDirectory);
        }
        int N = 1;
        List<byte[]> fileSegments = FileEncryption.splitFileToSegments(userFile.getFile());
        for (byte[] segment : fileSegments) {
          Path segmentFolder = Paths.get(filesDirectory.toString() + "\\" + N);
          if (!Files.exists(segmentFolder)) {
            Files.createDirectory(segmentFolder);
          }
          Path segmentPath = Paths.get(segmentFolder + "\\" + userFile.getFileName() + "_" + N);
          Files.write(segmentPath, segment);
          N += 1;
        }
        byte[] signature = FileEncryption.makeFileSignature(user.getUserKeyPair().getPrivate(),
            userFile.getFile());
        if (!Objects.isNull(signature)) {
          Path filesSignatures = Paths.get(getUserFilesSignaturesPath(user));
          if (!Files.exists(filesSignatures)) {
            Files.createDirectory(filesSignatures);
          }
          Path fileSignature = Paths.get(
              filesSignatures + "\\" + userFile.getFileName() + "_signature");
          Files.write(fileSignature, signature);
        } else {
          throw new Exception();
        }
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
  }

  public static boolean listFiles(User user) {

    File userRepository = new File(getUserFilesDirectoryPath(user));
    File[] segmentDirectories = userRepository.listFiles();

    if (segmentDirectories != null && segmentDirectories.length != 0) {
      File firstSegmentDirectory = segmentDirectories[0]; //jer svaki fajl ima sigurno prvi segment
      File[] files = firstSegmentDirectory.listFiles(); //uzimamo sve prve segmente kao predstavnike svaki za svoj fajl
      if (!Objects.isNull(files)) {
        for (File file : files) {
          System.out.println("File: " + file.getName().substring(0, file.getName().length() - 2));
        }
      }
      return true;
    } else {
      System.out.println("No files found.");
      return false;
    }
  }

  public static byte[] getFile(User user, String fileName) {

    try {
      List<byte[]> fileSegments = new ArrayList<>();
      byte[] fileSignature;
      File folder = new File(getUserFilesDirectoryPath(user));
      if (folder.isDirectory()) {
        File[] segmentDirectories = folder.listFiles();
        boolean tmp = true;
        if (segmentDirectories != null && segmentDirectories.length > 0) {
          for (File segmentDirectory : segmentDirectories) {
            if (segmentDirectory.isDirectory()) {
              //uzimamo samo segmente sa nazivom fajla koji nama treba
              FilenameFilter filter = (dir, name) -> name.substring(0, name.length() - 2)
                  .equals(fileName);
              File[] segments = segmentDirectory.listFiles(filter);
              //ako nema tog segmenta, znaci da nismo dobro unijeli fileName
              if (segments != null && segments.length > 0) {
                byte[] fileBytes = Files.readAllBytes(segments[0].toPath());
                fileSegments.add(fileBytes);
              }
            } else {
              //segmentDirectory is not a directory or it does not exist
              return null;
            }
            if (fileSegments.isEmpty()) {
              System.out.println("No such file: " + fileName + "\nMust enter the exact file name.");
              return null;
            }
          }

          //spajamo segmente u jedan cijeli fajl
          byte[] file = FileEncryption.mergeFileSegments(fileSegments);
          //dobavljamo potpis fajla
          fileSignature = getFileSignature(user, fileName);
          //verifikujemo potpis
          boolean isVerified = FileEncryption.verifyFileSignature(user.getUserKeyPair().getPublic(),
              file, fileSignature);
          if (isVerified) {
            return FileEncryption.decryptFile(file);
          } else {
            System.out.println("File has been corrupted!");
            //Files.write(Path.of("C:\\Users\\ozob9\\Desktop\\Kriptografija_Projekat\\"), Objects.requireNonNull(FileEncryption.decryptFile(file)));
            return null;
          }
        }
      }
      System.out.println("There are no uploaded files");
      return null;
    } catch (Exception e) {
      e.printStackTrace();
      return null;
    }
  }
}
