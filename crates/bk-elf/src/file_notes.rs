//! [`ElfFile`]'s readers for notes and informational sections.

use bk_bin::{ByteProvider, Endian};

use crate::constants::SegmentType;
use crate::file::ElfFile;
use crate::note::{
    ElfComment, ElfNote, GnuDebugAltLink, GnuDebugLink, NoteAbiTag, NoteError, NoteGnuBuildId,
    NoteGnuProperty, NoteIter,
};
use crate::program_header::ProgramHeader;
use crate::section_header::SectionHeader;

impl<P: ByteProvider> ElfFile<P> {
    /// The byte order notes and informational sections are read in: the
    /// file's data byte order (Ghidra reads them from program memory, whose
    /// byte order is the processor's).
    pub fn note_endian(&self) -> Endian {
        self.header().data_endian()
    }

    /// The notes in a section's data; iteration stops after an error.
    pub fn section_notes(&self, section: &SectionHeader) -> Vec<Result<ElfNote, NoteError>> {
        let data = self.section_data(section).unwrap_or_default();
        NoteIter::new(&data, self.note_endian()).collect()
    }

    /// The notes in a segment's data (a `PT_NOTE` segment, as Ghidra's
    /// `markupPtNote` reads them); iteration stops after an error.
    pub fn segment_notes(&self, segment: &ProgramHeader) -> Vec<Result<ElfNote, NoteError>> {
        let data = self.segment_data(segment).unwrap_or_default();
        NoteIter::new(&data, self.note_endian()).collect()
    }

    /// The notes of every `PT_NOTE` segment, in order.
    pub fn program_notes(&self) -> Vec<Result<ElfNote, NoteError>> {
        self.program_headers_of_type(SegmentType::PT_NOTE)
            .flat_map(|segment| self.segment_notes(segment))
            .collect()
    }

    /// The bytes of the first section named `name`, if there is one.
    fn named_section_data(&self, name: &str) -> Option<Vec<u8>> {
        let section = self.section_by_name(name)?;
        Some(self.section_data(section).ok()?.into_owned())
    }

    /// The first note of the section named `name`.
    fn first_note(&self, name: &str) -> Option<Result<ElfNote, NoteError>> {
        let data = self.named_section_data(name)?;
        NoteIter::new(&data, self.note_endian()).next()
    }

    /// `.note.ABI-tag`, if the file has that section.
    pub fn abi_tag(&self) -> Option<Result<NoteAbiTag, NoteError>> {
        let note = self.first_note(NoteAbiTag::SECTION_NAME)?;
        Some(note.and_then(|n| NoteAbiTag::from_note(n, self.note_endian())))
    }

    /// `.note.gnu.build-id`, if the file has that section.
    pub fn build_id(&self) -> Option<Result<NoteGnuBuildId, NoteError>> {
        let note = self.first_note(NoteGnuBuildId::SECTION_NAME)?;
        Some(note.and_then(NoteGnuBuildId::from_note))
    }

    /// `.note.gnu.property`, if the file has that section.
    pub fn gnu_property(&self) -> Option<Result<NoteGnuProperty, NoteError>> {
        let note = self.first_note(NoteGnuProperty::SECTION_NAME)?;
        let pointer_size = self.header().class.word_size();
        Some(note.and_then(|n| NoteGnuProperty::from_note(n, self.note_endian(), pointer_size)))
    }

    /// `.gnu_debuglink`, if the file has that section and it reads.
    pub fn debug_link(&self) -> Option<GnuDebugLink> {
        GnuDebugLink::read(
            &self.named_section_data(GnuDebugLink::SECTION_NAME)?,
            self.note_endian(),
        )
    }

    /// `.gnu_debugaltlink`, if the file has that section and it reads.
    pub fn debug_alt_link(&self) -> Option<GnuDebugAltLink> {
        GnuDebugAltLink::read(&self.named_section_data(GnuDebugAltLink::SECTION_NAME)?)
    }

    /// `.comment`, if the file has that section and it reads.
    pub fn comment(&self) -> Option<ElfComment> {
        ElfComment::read(&self.named_section_data(ElfComment::SECTION_NAME)?)
    }
}
