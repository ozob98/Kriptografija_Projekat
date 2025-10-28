package validators;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PKCS12PathValidator implements Validate {

    private FilePathValidator filePathValidator = new FilePathValidator();

    @Override
    public boolean validate(String filePath) {

        if (filePathValidator.validate(filePath)) {
            Path path = Paths.get(filePath);
            String fileName = path.getFileName().toString().toLowerCase();
            if (fileName.endsWith(".p12") || fileName.endsWith(".pkx")) {
                return Files.exists(path) || Files.isReadable(path);
            } else {
                System.out.println("Not PKCS12 file!");
                return false;
            }
        }
        else{
            return false;
        }
    }
}
