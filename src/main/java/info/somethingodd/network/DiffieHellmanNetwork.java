/* This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package info.somethingodd.network;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

/**
 * A network implementer using Diffie-Hellman encryption
 *
 * @author Gordon Pettey (petteyg359@gmail.com)
 */
public class DiffieHellmanNetwork extends BasicNetwork {
    private String cipherName;
    private static DHParameterSpec dhParameterSpec;
    private static byte[] p = new byte[]{
            (byte) 0x00, (byte) 0xF5, (byte) 0x81, (byte) 0xF6, (byte) 0x0F, (byte) 0x6D, (byte) 0xD0, (byte) 0x91,
            (byte) 0xD6, (byte) 0xF1, (byte) 0x54, (byte) 0xD8, (byte) 0xAD, (byte) 0x1A, (byte) 0xF8, (byte) 0xEB,
            (byte) 0x8E, (byte) 0x77, (byte) 0x36, (byte) 0xF7, (byte) 0x88, (byte) 0x50, (byte) 0x11, (byte) 0xD8,
            (byte) 0xDB, (byte) 0x9B, (byte) 0x80, (byte) 0x3B, (byte) 0xCB, (byte) 0x05, (byte) 0x28, (byte) 0x55,
            (byte) 0x58, (byte) 0x8D, (byte) 0x5B, (byte) 0x14, (byte) 0x93, (byte) 0x6A, (byte) 0xC3, (byte) 0xDA,
            (byte) 0x48, (byte) 0xB2, (byte) 0x57, (byte) 0x97, (byte) 0xF1, (byte) 0x07, (byte) 0xED, (byte) 0xDC,
            (byte) 0x36, (byte) 0xD7, (byte) 0x46, (byte) 0x9C, (byte) 0xE4, (byte) 0x49, (byte) 0xFF, (byte) 0xDC,
            (byte) 0xC5, (byte) 0x21, (byte) 0x9F, (byte) 0xD1, (byte) 0xA0, (byte) 0xC3, (byte) 0x7E, (byte) 0x06,
            (byte) 0xD4, (byte) 0xB7, (byte) 0xC5, (byte) 0x11, (byte) 0x67, (byte) 0x08, (byte) 0x23, (byte) 0x69,
            (byte) 0x07, (byte) 0x37, (byte) 0xD1, (byte) 0x17, (byte) 0x54, (byte) 0x0F, (byte) 0xCE, (byte) 0xB0,
            (byte) 0x55, (byte) 0x6E, (byte) 0x3E, (byte) 0xCD, (byte) 0xBC, (byte) 0xA7, (byte) 0x8D, (byte) 0x25,
            (byte) 0x27, (byte) 0xF2, (byte) 0x2F, (byte) 0x23, (byte) 0xBE, (byte) 0x03, (byte) 0x4E, (byte) 0xA1,
            (byte) 0x2F, (byte) 0x35, (byte) 0x33, (byte) 0xEC, (byte) 0x70, (byte) 0x0C, (byte) 0x73, (byte) 0xC1,
            (byte) 0x97, (byte) 0x0A, (byte) 0xBA, (byte) 0x9F, (byte) 0xE8, (byte) 0xE8, (byte) 0x40, (byte) 0x20,
            (byte) 0x88, (byte) 0x03, (byte) 0xEF, (byte) 0x14, (byte) 0x45, (byte) 0x6F, (byte) 0x5D, (byte) 0x83,
            (byte) 0x6E, (byte) 0xB7, (byte) 0xFE, (byte) 0x73, (byte) 0xCC, (byte) 0xD0, (byte) 0xE0, (byte) 0xEB,
            (byte) 0x13
    };
    private static byte[] g = new byte[]{(byte) 0x05};
    private static KeyPair keyPair;
    private SecretKey secretKey;

    static {
        try {
            dhParameterSpec = new DHParameterSpec(new BigInteger(p), new BigInteger(g), 1024);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
            keyPairGenerator.initialize(dhParameterSpec, SecureRandom.getInstance("SHA1PRNG"));
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    public DiffieHellmanNetwork() {
        super();
    }

    public DiffieHellmanNetwork(SocketChannel socketChannel) {
        super(socketChannel);
    }

    @Override
    public void setSocketChannel(SocketChannel socketChannel) {
        try {
            super.setSocketChannel(socketChannel);
            KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
            keyAgreement.init(keyPair.getPrivate(), dhParameterSpec);
            byte[] publicKey = keyPair.getPublic().getEncoded();
            sendRaw(publicKey);
            while (input.size() == 0) {
                try {
                    transfer(); // Have to do this manually at initialization.
                } catch (IOException e) {
                }
            }
            byte[] otherPublicKeyBytes = receiveRaw();
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(otherPublicKeyBytes);
            PublicKey otherPublicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            keyAgreement.doPhase(otherPublicKey, true);
            secretKey = keyAgreement.generateSecret("DES");
        } catch (GeneralSecurityException e) {
        }
    }

    @Override
    public String decrypt(byte[] message) {
        String plaintext;
        try {
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            plaintext = new String(cipher.doFinal(message), Charset.forName("UTF-8"));
        } catch (GeneralSecurityException e) {
            plaintext = "ERROR";
        }
        return plaintext;
    }

    @Override
    public byte[] encrypt(String message) {
        byte[] encrypted;
        try {
            Cipher cipher = Cipher.getInstance(cipherName);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            encrypted = cipher.doFinal(message.getBytes());
        } catch (GeneralSecurityException e) {
            encrypted = "ERROR".getBytes();
        }
        return encrypted;
    }
}