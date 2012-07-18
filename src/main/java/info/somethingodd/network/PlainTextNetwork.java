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

import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;

/**
 * A plain-text network implementation using dummy encryption methods
 *
 * @author Gordon Pettey (petteyg359@gmail.com)
 */
public class PlainTextNetwork extends BasicNetwork {

    public PlainTextNetwork() {
        super();
    }

    public PlainTextNetwork(SocketChannel socketChannel) {
        super(socketChannel);
    }

    @Override
    public String decrypt(byte[] message) {
        return new String(message, Charset.forName("UTF-8"));
    }

    @Override
    public byte[] encrypt(String message) {
        return message.getBytes();
    }
}