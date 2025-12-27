package app.aoki.yuki.hcefhook.core;

/**
 * Helper class to build SENSF_RES frames
 */
public class SensfResBuilder {
    
    private byte[] idm = Constants.DEFAULT_IDM;
    private byte[] pmm = Constants.DEFAULT_PMM;
    private byte[] rd = null;  // Optional Request Data
    
    public SensfResBuilder() {
    }
    
    /**
     * Set custom IDm (8 bytes)
     */
    public SensfResBuilder setIdm(byte[] idm) {
        if (idm == null || idm.length != 8) {
            throw new IllegalArgumentException("IDm must be exactly 8 bytes");
        }
        this.idm = idm.clone();
        return this;
    }
    
    /**
     * Set custom PMm (8 bytes)
     */
    public SensfResBuilder setPmm(byte[] pmm) {
        if (pmm == null || pmm.length != 8) {
            throw new IllegalArgumentException("PMm must be exactly 8 bytes");
        }
        this.pmm = pmm.clone();
        return this;
    }
    
    /**
     * Set optional Request Data (0-2 bytes)
     */
    public SensfResBuilder setRd(byte[] rd) {
        if (rd != null && rd.length > 2) {
            throw new IllegalArgumentException("RD must be 0-2 bytes");
        }
        this.rd = rd != null ? rd.clone() : null;
        return this;
    }
    
    /**
     * Build the SENSF_RES frame
     * Format: [Length][0x01][IDm 8B][PMm 8B][RD 0-2B]
     */
    public byte[] build() {
        int rdLen = (rd != null) ? rd.length : 0;
        int totalLen = 1 + 8 + 8 + rdLen;  // cmd(1) + IDm(8) + PMm(8) + RD(0-2)
        
        byte[] frame = new byte[1 + totalLen];  // +1 for length byte
        int offset = 0;
        
        // Length byte (total frame size including length byte itself)
        frame[offset++] = (byte)(totalLen + 1);
        
        // Response command code
        frame[offset++] = Constants.SENSF_RES_CMD;
        
        // IDm (8 bytes)
        System.arraycopy(idm, 0, frame, offset, 8);
        offset += 8;
        
        // PMm (8 bytes)
        System.arraycopy(pmm, 0, frame, offset, 8);
        offset += 8;
        
        // Optional RD
        if (rd != null && rd.length > 0) {
            System.arraycopy(rd, 0, frame, offset, rd.length);
        }
        
        return frame;
    }
    
    /**
     * Build with default values
     */
    public static byte[] buildDefault() {
        return new SensfResBuilder().build();
    }
    
    /**
     * Convert byte array to hex string for logging
     */
    public static String toHexString(byte[] data) {
        if (data == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
}
