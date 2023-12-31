#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(i8)]
pub enum TxPower {
    #[cfg(any(feature = "ch57x", feature = "ch59x"))]
    Minus20dBm = -20,
    #[cfg(feature = "ch32v208")]
    Minus18dBm = -18,
    #[cfg(feature = "ch58x")]
    Minus16dBm = -16,
    #[cfg(feature = "ch59x")]
    Minus15dBm = -15,
    #[cfg(feature = "ch57x")]
    Minus14dBm = -14,
    #[cfg(feature = "ch58x")]
    Minus12dBm = -12,
    #[cfg(feature = "ch32v208")]
    Minus10dBm = -10,
    #[cfg(any(feature = "ch57x", feature = "ch58x", feature = "ch59x"))]
    Minus8dBm = -8,
    #[cfg(any(feature = "ch58x", feature = "ch32v20x"))]
    Minus5dBm = -5,
    #[cfg(feature = "ch57x")]
    Minus4dBm = -4,
    #[cfg(any(feature = "ch58x", feature = "ch32v20x"))]
    Minus3dBm = -3,
    #[cfg(any(feature = "ch58x", feature = "ch59x"))]
    Minus1dBm = -1,

    ZerodBm = 0,
    Plus1dBm = 1,
    Plus2dBm = 2,
    Plus3dBm = 3,
    Plus4dBm = 4,
    #[cfg(any(feature = "ch57x", feature = "ch58x", feature = "ch32v20x"))]
    Plus5dBm = 5,
    #[cfg(any(feature = "ch57x", feature = "ch58x", feature = "ch32v20x"))]
    Plus6dBm = 6,
    #[cfg(any(feature = "ch57x", feature = "ch32v20x"))]
    Plus7dBm = 7,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum Phy {
    /// 1Mbps phy
    M1 = 1,
    /// 2Mbps phy
    M2 = 2,
    /// Coded phy (125kbps, S=8)
    Coded = 4,
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Eq, PartialEq, Copy, Clone)]
#[repr(u8)]
pub enum PhySet {
    /// 1Mbps phy
    M1 = 1,
    /// 2Mbps phy
    M2 = 2,
    /// 1Mbps + 2Mbps phys
    M1M2 = 3,
    /// Coded phy (125kbps, S=8)
    Coded = 4,
    /// 1Mbps and Coded phys
    M1Coded = 5,
    /// 2Mbps and Coded phys
    M2Coded = 6,
    /// 1Mbps, 2Mbps and Coded phys
    M1M2Coded = 7,
}
