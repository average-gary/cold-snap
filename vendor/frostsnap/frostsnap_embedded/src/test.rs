use alloc::boxed::Box;
use embedded_storage::nor_flash;

pub struct TestNorFlash(pub Box<[u8; 4096 * 4]>);
const WORD_SIZE: u32 = 4;

impl Default for TestNorFlash {
    fn default() -> Self {
        Self::new()
    }
}

impl TestNorFlash {
    pub fn new() -> Self {
        Self(Box::new([0xffu8; 4096 * 4]))
    }
}

impl nor_flash::ErrorType for TestNorFlash {
    type Error = core::convert::Infallible;
}

impl nor_flash::ReadNorFlash for TestNorFlash {
    const READ_SIZE: usize = 1;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        bytes.copy_from_slice(&self.0[offset as usize..offset as usize + bytes.len()]);
        Ok(())
    }

    fn capacity(&self) -> usize {
        4096 * 4
    }
}

impl nor_flash::NorFlash for TestNorFlash {
    const WRITE_SIZE: usize = WORD_SIZE as usize;
    const ERASE_SIZE: usize = 4096;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        self.0[from as usize..to as usize].fill(0xff);
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        assert!(offset.is_multiple_of(WORD_SIZE));
        assert!(bytes.len().is_multiple_of(4));
        self.0[offset as usize..offset as usize + bytes.len()].copy_from_slice(bytes);

        Ok(())
    }
}

/// `TestNorFlash` with injectable program/erase failures.
///
/// `TestNorFlash`'s error type is [`core::convert::Infallible`], so with it alone
/// **no** flash-error path in this crate is reachable from a host test — every
/// `.expect("must erase")`-class site is untestable. STM32 program/erase really
/// can fail (`PROGERR`/`WRPERR`), which is the whole reason those sites matter,
/// so testing the recovery contract requires a flash that can say no.
///
/// Failures are scheduled by *operation count* rather than by address so a test
/// can target "the second erase of this write" without knowing the layout.
pub struct FaultyNorFlash {
    inner: TestNorFlash,
    /// Erase calls remaining before erases start failing; `None` = never fail.
    fail_erase_after: Option<usize>,
    /// Write calls remaining before writes start failing; `None` = never fail.
    fail_write_after: Option<usize>,
    erases: usize,
    writes: usize,
}

/// Distinguishable so a test can assert *which* operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultyError {
    EraseRefused,
    WriteRefused,
}

impl nor_flash::NorFlashError for FaultyError {
    fn kind(&self) -> nor_flash::NorFlashErrorKind {
        nor_flash::NorFlashErrorKind::Other
    }
}

impl Default for FaultyNorFlash {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultyNorFlash {
    pub fn new() -> Self {
        Self {
            inner: TestNorFlash::new(),
            fail_erase_after: None,
            fail_write_after: None,
            erases: 0,
            writes: 0,
        }
    }

    /// Fail every erase from the `n`th (0-based) onward.
    pub fn fail_erase_after(&mut self, n: usize) {
        self.fail_erase_after = Some(n);
    }

    /// Fail every write from the `n`th (0-based) onward.
    pub fn fail_write_after(&mut self, n: usize) {
        self.fail_write_after = Some(n);
    }

    /// Stop injecting failures. Lets a test observe the state a fault left
    /// behind, e.g. that a committed value is still readable afterwards.
    pub fn heal(&mut self) {
        self.fail_erase_after = None;
        self.fail_write_after = None;
    }

    pub fn erase_count(&self) -> usize {
        self.erases
    }

    pub fn write_count(&self) -> usize {
        self.writes
    }
}

impl nor_flash::ErrorType for FaultyNorFlash {
    type Error = FaultyError;
}

impl nor_flash::ReadNorFlash for FaultyNorFlash {
    const READ_SIZE: usize = <TestNorFlash as nor_flash::ReadNorFlash>::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let Ok(()) = nor_flash::ReadNorFlash::read(&mut self.inner, offset, bytes);
        Ok(())
    }

    fn capacity(&self) -> usize {
        nor_flash::ReadNorFlash::capacity(&self.inner)
    }
}

impl nor_flash::NorFlash for FaultyNorFlash {
    const WRITE_SIZE: usize = <TestNorFlash as nor_flash::NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <TestNorFlash as nor_flash::NorFlash>::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), Self::Error> {
        let n = self.erases;
        self.erases += 1;
        if self.fail_erase_after.is_some_and(|start| n >= start) {
            // Refused outright, exactly like a driver that checks SR before
            // touching the array: the sector is left as it was.
            return Err(FaultyError::EraseRefused);
        }
        let Ok(()) = nor_flash::NorFlash::erase(&mut self.inner, from, to);
        Ok(())
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Self::Error> {
        let n = self.writes;
        self.writes += 1;
        if self.fail_write_after.is_some_and(|start| n >= start) {
            return Err(FaultyError::WriteRefused);
        }
        let Ok(()) = nor_flash::NorFlash::write(&mut self.inner, offset, bytes);
        Ok(())
    }
}
