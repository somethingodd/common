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

import java.io.IOException;
import java.nio.channels.SocketChannel;

/**
 * @author Gordon Pettey (petteyg359@gmail.com)
 */
public interface Network extends Runnable {
    /**
     * This method should return the socketChannel used by the implementation
     * @return SocketChannel in use
     */
    public SocketChannel getSocketChannel();

    /**
     * This method should set the socketChannel to a new socketChannel.
     * This supports making the object final for thread safety, while allow disconnection/reconnection.
     * @param socketChannel SocketChannel to use
     */
    public void setSocketChannel(SocketChannel socketChannel);

    /**
     * @param message encrypted message
     * @return raw message
     */
    public String decrypt(byte[] message);

    /**
     * @param message raw message
     * @return encrypted message
     */
    public byte[] encrypt(String message);

    /**
     * This method should return whether the network is connected
     * @return status
     */
    public boolean isAvailable();

    /**
     * This method should return the top of the input buffer after passing it through {@link #decrypt(byte[])}
     * @return decrypted message
     */
    public String receive();

    /**
     * This method should return the top of the input buffer
     * @return raw message
     */
    public byte[] receiveRaw();

    /**
     * This method should pass a message through {@link #encrypt(String)} and then place it in the output buffer
     * @param message message to send
     */
    public void send(String message);

    /**
     * This method should put a message in the output buffer with no encryption
     * @param message message to send
     */
    public void sendRaw(byte[] message);

    /**
     * This method should transmit/receive any data in buffers
     * @throws java.io.IOException socketChannel
     */
    public void transfer() throws IOException;

    /**
     * This method should cause the running thread to end execution
     */
    public void stop();
}