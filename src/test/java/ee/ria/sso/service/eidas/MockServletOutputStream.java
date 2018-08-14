package ee.ria.sso.service.eidas;

import javax.servlet.ServletOutputStream;
import java.io.IOException;

public class MockServletOutputStream extends ServletOutputStream {

    private byte[] writtenContent;
    private boolean open = true;

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (!this.open) throw new IOException("Cannot write into closed stream!");
        if (off < 0 || off + len > b.length) throw new IndexOutOfBoundsException();

        final int offset = this.expandInternalBufferAndReturnOffset(len);
        System.arraycopy(b, off, this.writtenContent, offset, len);
    }

    @Override
    public void write(int b) throws IOException {
        if (!this.open) throw new IOException("Cannot write into closed stream!");
        final int offset = this.expandInternalBufferAndReturnOffset(1);
        this.writtenContent[offset] = (byte) (b & 0xff);
    }

    @Override
    public void flush() throws IOException {
        if (!this.open) throw new IOException("Cannot flush a closed stream!");
    }

    @Override
    public void close() throws IOException {
        if (!this.open) throw new IOException("Stream is already closed!");
        this.open = false;
    }

    private int expandInternalBufferAndReturnOffset(int size) {
        final int oldSize = (this.writtenContent != null) ? this.writtenContent.length : 0;
        final byte[] newBuffer = new byte[oldSize + size];

        if (this.writtenContent != null)
            System.arraycopy(this.writtenContent, 0, newBuffer, 0, oldSize);
        this.writtenContent = newBuffer;

        return oldSize;
    }

    public byte[] getWrittenContent() throws IllegalStateException {
        if (this.open) throw new IllegalStateException("Stream is still open!");
        return this.writtenContent;
    }

}
