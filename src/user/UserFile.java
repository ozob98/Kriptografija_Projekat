package user;

public class UserFile {

  private String fileName;
  private byte[] file;
//    private String filePath;
//    private byte[] keyBytes;
//    private byte[] iv;

//    public byte[] getKeyBytes(){ return keyBytes; }
//    public void setKeyBytes(byte[] keyBytes){ this.keyBytes = keyBytes; }
//    public byte[] getIV(){ return iv; }
//    public void setIV(byte[] iv){ this.iv = iv; }

  public void setFile(byte[] file) {
    this.file = file;
  }

  public byte[] getFile() {
    return file;
  }

  public void setFileName(String fileName) {
    this.fileName = fileName;
  }

  public String getFileName() {
    return fileName;
  }

  //    public void setFilePath(String filePath){
//        this.filePath = filePath;
//    }
//
//    public String getFilePath(){
//        return filePath;
//    }
  public String getFileExtension() {

    int dotIndex = fileName.lastIndexOf('.');
    return fileName.substring(dotIndex + 1);
  }

  public String toString() {
    return "File Name: " + fileName + "\nFile extension: " + getFileExtension();
  }


}
