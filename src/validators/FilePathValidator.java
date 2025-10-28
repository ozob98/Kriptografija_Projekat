package validators;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FilePathValidator implements Validate {

    private static final String WINDOWS_FILE_PATH_PATTERN = "^(?<ParentPath>(?:[a-zA-Z]\\:|\\\\\\\\[\\w\\s\\.]+\\\\[\\w\\s\\.$]+)\\\\(?:[\\w\\s\\.]+\\\\)*)(?<BaseName>[\\w\\s\\.]*?)$";

    @Override
    public boolean validate(String filePath) {
        Pattern pattern = Pattern.compile(WINDOWS_FILE_PATH_PATTERN);
        Matcher matcher = pattern.matcher(filePath);

        if (!matcher.matches()) {
            System.out.println("Invalid file path");
            return false;
        } else {
            return true;
        }
    }
}
