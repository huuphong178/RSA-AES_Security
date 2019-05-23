package com.app;

import com.app.RSA.DemoRSA;
import com.app.RSA.GenerateKeys;
import com.app.callAPI.Helper;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;


import static com.app.RSA.DemoRSA.decryptedRSA;

public class app {
    private JButton btnGetRoom;
    private JPanel panel1;
    private JTextArea txtResult;
    private JButton btnGetSecretKey;

    private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    public static String randomAlphaNumeric(int count) {
        StringBuilder builder = new StringBuilder();
        while (count-- != 0) {
            int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
            builder.append(ALPHA_NUMERIC_STRING.charAt(character));
        }
        return builder.toString();
    }
    public app() {

        btnGetRoom.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.out.println("Phong");
               // JOptionPane.showMessageDialog(null, "My Goodness, this is so concise");

                String temp= null;
                try {
                    temp = Helper.encryptAESData(Helper.POST_PARAMS);
                    txtResult.setText(txtResult.getText()+"Post request da ma hoa: "+temp+"\n");
                    //Them signature vao data
                    String header= DemoRSA.enryptedSignature(Helper.POST_PARAMS);
                    System.out.println("Header: "+header);
                    String reponse=Helper.postRequest(temp,header);
                    txtResult.setText(txtResult.getText()+"Reponse: "+reponse+"\n");
                    String decrypted=Helper.decryptAESData(reponse);
                    txtResult.setText(txtResult.getText()+"Giai ma: "+decrypted+"\n");
                } catch (Exception ex) {
                    ex.printStackTrace();
                }

            }
        });
        btnGetSecretKey.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String secret_Key= null;
                try {
                    secret_Key = Helper.getSecretKeyFromServer();
                    txtResult.setText(txtResult.getText()+"Secret Key nhan duoc: "+secret_Key+"\n");
                    String secretDecrypted=decryptedRSA(secret_Key);
                    GenerateKeys.writeToFile(GenerateKeys.SECRET_KEY_FILE,secretDecrypted.getBytes());
                    txtResult.setText(txtResult.getText()+"Giai ma: "+secretDecrypted+"\n");

                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
        });
    }
    public static void main(String[] args) throws Exception {

        JFrame jFrame=new JFrame("App");
        jFrame.setContentPane(new app().panel1);
        jFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        jFrame.setPreferredSize(new Dimension(600, 700));
        jFrame.pack();
        jFrame.setLocationRelativeTo(null);
        jFrame.setVisible(true );
    }
}
