package me.braydon.antivpn.common;

import inet.ipaddr.IPAddress;
import lombok.NonNull;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * An immutable set of IPv4 and IPv6 CIDR blocks
 * that supports fast containment lookups.
 * <p>
 * Every address is mapped into a single 128-bit space
 * (IPv4 lives in ::ffff:0:0/96), blocks nested inside
 * other blocks are dropped, and lookups are a binary
 * search over the remaining disjoint blocks.
 * </p>
 *
 * @author Braydon
 */
public final class IpRangeIndex {
    private static final IpRangeIndex EMPTY = new IpRangeIndex(new long[0], new long[0], new long[0], new long[0], new String[0]);
    
    private final long[] startHi, startLo, endHi, endLo;
    
    /**
     * The canonical CIDR notation of each block.
     */
    private final String[] blocks;
    
    private IpRangeIndex(long[] startHi, long[] startLo, long[] endHi, long[] endLo, String[] blocks) {
        this.startHi = startHi;
        this.startLo = startLo;
        this.endHi = endHi;
        this.endLo = endLo;
        this.blocks = blocks;
    }
    
    /**
     * Get an empty index.
     *
     * @return the empty index
     */
    @NonNull
    public static IpRangeIndex empty() {
        return EMPTY;
    }
    
    /**
     * Build an index from the given CIDR blocks or single
     * addresses, invalid entries are silently skipped.
     *
     * @param entries the entries
     * @return the index
     */
    @NonNull
    public static IpRangeIndex of(@NonNull Collection<String> entries) {
        List<IPAddress> addresses = new ArrayList<>(entries.size());
        for (String entry : entries) {
            IPUtils.parse(entry).ifPresent(addresses::add);
        }
        return ofAddresses(addresses);
    }
    
    /**
     * Build an index from the given CIDR blocks or single addresses.
     *
     * @param addresses the addresses
     * @return the index
     */
    @NonNull
    public static IpRangeIndex ofAddresses(@NonNull Collection<IPAddress> addresses) {
        if (addresses.isEmpty()) {
            return EMPTY;
        }
        List<Block> sorted = new ArrayList<>(addresses.size());
        for (IPAddress address : addresses) {
            sorted.add(Block.of(address));
        }
        sorted.sort(Comparator.comparing((Block block) -> block.start).thenComparing(block -> block.end, Comparator.reverseOrder()));
        
        List<Block> disjoint = new ArrayList<>(sorted.size());
        U128 lastEnd = null;
        for (Block block : sorted) {
            // CIDR blocks are either disjoint or nested, so anything
            // starting before the previous end is inside the previous block
            if (lastEnd != null && block.start.compareTo(lastEnd) <= 0) {
                continue;
            }
            disjoint.add(block);
            lastEnd = block.end;
        }
        int size = disjoint.size();
        long[] startHi = new long[size], startLo = new long[size], endHi = new long[size], endLo = new long[size];
        String[] blocks = new String[size];
        for (int i = 0; i < size; i++) {
            Block block = disjoint.get(i);
            startHi[i] = block.start.hi;
            startLo[i] = block.start.lo;
            endHi[i] = block.end.hi;
            endLo[i] = block.end.lo;
            blocks[i] = block.cidr;
        }
        return new IpRangeIndex(startHi, startLo, endHi, endLo, blocks);
    }
    
    /**
     * Find the block containing the given address.
     *
     * @param address the address
     * @return the CIDR notation of the block, empty if none
     */
    @NonNull
    public Optional<String> find(@NonNull IPAddress address) {
        U128 value = U128.lower(address);
        int index = floor(value.hi, value.lo);
        if (index < 0 || compare(endHi[index], endLo[index], value.hi, value.lo) < 0) {
            return Optional.empty();
        }
        return Optional.of(blocks[index]);
    }
    
    /**
     * Check if the given address is in this index.
     *
     * @param address the address
     * @return true if contained, otherwise false
     */
    public boolean contains(@NonNull IPAddress address) {
        return find(address).isPresent();
    }
    
    /**
     * Check if any part of the given address or
     * block overlaps a block in this index.
     *
     * @param address the address or block
     * @return true if it overlaps, otherwise false
     */
    public boolean overlaps(@NonNull IPAddress address) {
        Block block = Block.of(address);
        int index = floor(block.end.hi, block.end.lo);
        return index >= 0 && compare(endHi[index], endLo[index], block.start.hi, block.start.lo) >= 0;
    }
    
    /**
     * Get the amount of disjoint blocks in this index.
     *
     * @return the amount of blocks
     */
    public int size() {
        return blocks.length;
    }
    
    /**
     * Get the canonical CIDR notation of every block in this index.
     *
     * @return the blocks
     */
    @NonNull
    public List<String> getBlocks() {
        return Collections.unmodifiableList(Arrays.asList(blocks));
    }
    
    /**
     * Find the index of the last block whose start is {@code <=} the given value.
     */
    private int floor(long hi, long lo) {
        int low = 0, high = blocks.length - 1, result = -1;
        while (low <= high) {
            int mid = (low + high) >>> 1;
            if (compare(startHi[mid], startLo[mid], hi, lo) <= 0) {
                result = mid;
                low = mid + 1;
            } else {
                high = mid - 1;
            }
        }
        return result;
    }
    
    private static int compare(long aHi, long aLo, long bHi, long bLo) {
        int hi = Long.compareUnsigned(aHi, bHi);
        return hi != 0 ? hi : Long.compareUnsigned(aLo, bLo);
    }
    
    private record U128(long hi, long lo) implements Comparable<U128> {
        private static final long IPV4_MAPPED_PREFIX = 0x0000FFFF00000000L;
        
        @NonNull
        static U128 lower(@NonNull IPAddress address) {
            return of(address.getLower());
        }
        
        @NonNull
        static U128 upper(@NonNull IPAddress address) {
            return of(address.getUpper());
        }
        
        @NonNull
        private static U128 of(@NonNull IPAddress address) {
            byte[] bytes = address.getBytes();
            if (bytes.length == 4) {
                return new U128(0L, IPV4_MAPPED_PREFIX | (ByteBuffer.wrap(bytes).getInt() & 0xFFFFFFFFL));
            }
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            return new U128(buffer.getLong(), buffer.getLong());
        }
        
        @Override
        public int compareTo(@NonNull U128 other) {
            return compare(hi, lo, other.hi, other.lo);
        }
    }
    
    private record Block(U128 start, U128 end, String cidr) {
        @NonNull
        static Block of(@NonNull IPAddress address) {
            IPAddress block = address.isPrefixed() ? address.toPrefixBlock() : address;
            return new Block(U128.lower(block), U128.upper(block), block.toCanonicalString());
        }
    }
}
