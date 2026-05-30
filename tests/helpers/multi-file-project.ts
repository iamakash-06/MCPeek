import { Project, SourceFile } from "ts-morph";

export interface InMemoryFile {
  name: string;
  code: string;
}

export function makeMultiFileProject(files: InMemoryFile[]): Project {
  const project = new Project({ useInMemoryFileSystem: true });
  for (const { name, code } of files) {
    project.createSourceFile(name, code);
  }
  return project;
}

export function getFile(project: Project, name: string): SourceFile {
  return project.getSourceFileOrThrow(name);
}
