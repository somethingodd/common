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
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * An abtract network implementation
 *
 * This implementation may operate a thread independently. The {@link #run()}
 * method runs {@link #transfer()} until {@link #stop()} is called. It may be
 * operated from another thread, simply by calling {@link #transfer()} in a loop.
 *
 * @author Gordon Pettey (petteyg359@gmail.com)
 */
public abstract class BasicNetwork implements Network {
    protected boolean stop;
    protected SocketChannel socketChannel;
    protected ByteBuffer inputBuffer;
    protected final Queue<byte[]> input;
    protected final Queue<byte[]> output;

    public BasicNetwork() {
        input = new LinkedBlockingQueue<byte[]>();
        output = new LinkedBlockingQueue<byte[]>();
    }

    public BasicNetwork(SocketChannel socketChannel) {
        this();
        setSocketChannel(socketChannel);
    }

    public SocketChannel getSocketChannel() {
        return socketChannel;
    }

    public void setSocketChannel(SocketChannel socketChannel) {
        this.socketChannel = socketChannel;
    }

    @Override
    public abstract String decrypt(byte[] message);

    @Override
    public abstract byte[] encrypt(String message);

    @Override
    public boolean isAvailable() {
        return (socketChannel != null && socketChannel.isConnected() && !input.isEmpty());
    }

    /**
     * Retrieves data from {@link #input} and passes it through {@link #decrypt(byte[])}
     *
     * @return decrypted data
     */
    @Override
    public String receive() {
        synchronized (input) {
            String in = decrypt(input.poll());
            return in;
        }
    }

    /**
     * Retrieves data from {@link #input}
     *
     * @return raw data
     */
    @Override
    public byte[] receiveRaw() {
        synchronized (input) {
            byte[] in = input.poll();
            return in;
        }
    }

    /**
     * Adds data to {@link #output} after passing it through {@link #encrypt(String)}
     *
     * @param message data to be encrypted and sent
     */
    @Override
    public void send(String message) {
        synchronized (output) {
            byte[] out = encrypt(message);
            output.offer(out);
        }
    }


    /**
     * Adds data to {@link #output} without encryption
     *
     * @param message data to be sent
     */
    @Override
    public void sendRaw(byte[] message) {
        synchronized (output) {
            output.offer(message);
        }
    }


    /**
     * Transmits data
     *
     * Checks for data in {@link #output}, and sends the first element, if found.
     * Checks for data from the {@link #socketChannel}, and reads all available bytes into {@link #inputBuffer}.
     * When {@link #inputBuffer} is full, puts bytes in {@link #input}.
     *
     * @throws java.io.IOException on {@link #socketChannel} error
     */
    @Override
    public synchronized void transfer() throws IOException {
        byte[] message;
        synchronized (output) {
            message = output.poll();
        }
        if (message != null) {
            ByteBuffer byteBuffer = ByteBuffer.allocate(4 /* size of int */ + message.length);
            byteBuffer.putInt(message.length);
            byteBuffer.put(message);
            byteBuffer.rewind();
            socketChannel.write(byteBuffer);
        }
        if (inputBuffer == null) { /* inputBuffer is ready to receive new data */
            inputBuffer = ByteBuffer.allocate(4); /* set size to receive length */
        }
        if (inputBuffer.remaining() != 0) {
            socketChannel.read(inputBuffer);
        } else {
            if (inputBuffer.capacity() == 4) {
                inputBuffer.rewind();
                int length = inputBuffer.getInt();
                inputBuffer = ByteBuffer.allocate(length);
            } else {
                inputBuffer.rewind();
                synchronized (input) {
                    byte[] in = inputBuffer.array();
                    input.offer(in);
                }
                inputBuffer = null;
            }
        }
    }

    /**
     * Loops {@link #transfer()} until {@link #stop} is true
     */
    @Override
    public void run() {
        try {
            while (!stop) {
                transfer();
            }
        } catch (IOException e) {
        }
    }

    /**
     * Sets {@link #stop} for thread to stop
     */
    @Override
    public void stop() {
        stop = true;
    }
}