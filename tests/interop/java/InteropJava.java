import net.i2p.data.Base32;
import net.i2p.data.Base64;
import net.i2p.data.Destination;

/**
 * Cross-validates i2pbox outputs against the i2p-java implementation's
 * independent codecs. Compiled against net.i2p:i2p from Maven Central.
 *
 * Subcommands (called by tests/interop/run_interop.sh):
 *   base64-encode <hex>
 *   base64-decode <b64> <expected-hex>
 *   destination <dest-b64> <expected-b32> <expected-hash-b64>
 */
public class InteropJava {
    static void die(String msg) {
        System.err.println("interop_java: " + msg);
        System.exit(1);
    }

    static byte[] hex(String s) {
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2)
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        return out;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 2) die("usage: InteropJava <subcommand> ...");
        String cmd = args[0];
        switch (cmd) {
        case "base64-encode": {
            if (args.length != 2) die("usage: base64-encode <hex>");
            System.out.println(Base64.encode(hex(args[1])));
            break;
        }
        case "base64-decode": {
            if (args.length != 3) die("usage: base64-decode <b64> <expected-hex>");
            byte[] raw = Base64.decode(args[1]);
            if (!hex(raw).equals(args[2]))
                die("decode mismatch: got " + hex(raw) + " want " + args[2]);
            System.out.println("ok");
            break;
        }
        case "destination": {
            if (args.length != 4) die("usage: destination <dest-b64> <expected-b32> <expected-hash-b64>");
            byte[] raw = Base64.decode(args[1]);
            Destination d = new Destination();
            try {
                int n = d.readBytes(raw, 0);
                if (n != raw.length)
                    die("destination trailing data: read " + n + " of " + raw.length);
            } catch (Exception e) {
                die("destination parse failed: " + e);
            }
            byte[] h = d.getHash().getData();
            String b32 = Base32.encode(h).toLowerCase();
            String wantB32 = args[2].toLowerCase().replace(".b32.i2p", "");
            if (!b32.equals(wantB32))
                die("b32 mismatch: i2p-java=" + b32 + " i2pbox=" + args[2]);
            String hb64 = Base64.encode(h);
            if (!hb64.equals(args[3]))
                die("hash base64 mismatch: i2p-java=" + hb64 + " i2pbox=" + args[3]);
            System.out.println("ok");
            break;
        }
        default:
            die("unknown subcommand " + cmd);
        }
    }
}
