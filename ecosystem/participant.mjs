import {encodeDocument,decodeDocument} from './document-exchange.mjs';
export const REPOSITORY = "Maurits-pixe/palaco-genesis";
export async function exportDocument(document, reference) {
  if (reference?.repository !== REPOSITORY) throw new Error('SOURCE_REPOSITORY_MISMATCH');
  return encodeDocument(reference, document);
}
export const readDocument = decodeDocument;
