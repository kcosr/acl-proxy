export interface ParsedRequest {
  method: string;
  path: string;
  protocol: string;
  headers: Record<string, string>;
  body: Buffer | null;
}

export type OnRequest = (request: ParsedRequest) => void;

export default class HTTPParser {
  private onRequest: OnRequest;
  private buffer: Buffer = Buffer.alloc(0);
  private headersParsed = false;
  private method: string | null = null;
  private path: string | null = null;
  private protocol: string | null = null;
  private headers: Record<string, string> = {};
  private contentLength = 0;
  private bodyStartIndex = -1;
  private isChunked = false;
  private currentChunkSize: number | null = null;
  private chunks: Buffer[] | null = null;

  constructor(onRequest: OnRequest) {
    this.onRequest = onRequest;
    this.reset();
  }

  reset(): void {
    this.buffer = Buffer.alloc(0);
    this.headersParsed = false;
    this.method = null;
    this.path = null;
    this.protocol = null;
    this.headers = {};
    this.contentLength = 0;
    this.bodyStartIndex = -1;
    this.isChunked = false;
    this.currentChunkSize = null;
    this.chunks = null;
  }

  parse(data: Buffer): void {
    this.buffer = Buffer.concat([this.buffer, data]);
    while (this.processBuffer()) {
      // keep processing until buffer is fully handled
    }
  }

  private processBuffer(): boolean {
    if (!this.headersParsed) {
      const headerEndIndex = this.buffer.indexOf('\r\n\r\n');
      if (headerEndIndex === -1) return false;
      const headerString = this.buffer.slice(0, headerEndIndex).toString();
      const lines = headerString.split('\r\n');
      const [method, path, protocol] = lines[0].split(' ');
      if (!method || !path || !protocol) {
        this.reset();
        return false;
      }
      this.method = method;
      this.path = path;
      this.protocol = protocol;
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx > 0) {
          const key = lines[i].slice(0, idx).trim().toLowerCase();
          const value = lines[i].slice(idx + 1).trim();
          this.headers[key] = value;
        }
      }
      this.isChunked = !!(
        this.headers['transfer-encoding'] &&
        /chunked/i.test(this.headers['transfer-encoding'])
      );
      this.contentLength =
        !this.isChunked && this.headers['content-length']
          ? parseInt(this.headers['content-length'], 10)
          : 0;
      this.headersParsed = true;
      this.bodyStartIndex = headerEndIndex + 4;
    }
    if (this.isChunked) {
      if (!this.chunks) this.chunks = [];
      let idx = this.bodyStartIndex;
      while (true) {
        if (this.currentChunkSize === null) {
          const lineEnd = this.buffer.indexOf('\r\n', idx);
          if (lineEnd === -1) return false;
          const size = parseInt(
            this.buffer
              .slice(idx, lineEnd)
              .toString()
              .split(';')[0]
              .trim(),
            16
          );
          if (isNaN(size) || size < 0) {
            this.reset();
            return false;
          }
          this.currentChunkSize = size;
          idx = lineEnd + 2;
          if (size === 0) {
            const trailerEnd = this.buffer.indexOf('\r\n\r\n', idx);
            const simpleEnd = this.buffer.indexOf('\r\n', idx);
            if (trailerEnd === -1 && simpleEnd === -1) return false;
            const endIdx =
              trailerEnd !== -1 ? trailerEnd + 4 : simpleEnd + 2;
            this.emitRequestChunked(Buffer.concat(this.chunks), endIdx);
            return true;
          }
        }
        const available = this.buffer.length - idx;
        if (available < (this.currentChunkSize as number) + 2) return false;
        const chunk = this.buffer.slice(
          idx,
          idx + (this.currentChunkSize as number)
        );
        this.chunks.push(chunk);
        idx += this.currentChunkSize as number;
        if (this.buffer.slice(idx, idx + 2).toString() !== '\r\n') {
          this.reset();
          return false;
        }
        idx += 2;
        this.currentChunkSize = null;
      }
    }
    const bodyLength = this.buffer.length - this.bodyStartIndex;
    if (
      this.method &&
      ['GET', 'HEAD', 'DELETE', 'CONNECT'].includes(
        this.method.toUpperCase()
      ) &&
      this.contentLength === 0
    ) {
      this.emitRequest();
      return true;
    }
    if (this.contentLength > 0 && bodyLength >= this.contentLength) {
      this.emitRequest();
      return true;
    }
    return false;
  }

  private emitRequest(): void {
    const body =
      this.contentLength > 0
        ? this.buffer.slice(
            this.bodyStartIndex,
            this.bodyStartIndex + this.contentLength
          )
        : null;
    this.onRequest({
      method: this.method as string,
      path: this.path as string,
      protocol: this.protocol as string,
      headers: this.headers,
      body
    });
    const totalLen = this.bodyStartIndex + this.contentLength;
    if (this.buffer.length > totalLen) {
      const leftover = this.buffer.slice(totalLen);
      this.reset();
      this.buffer = leftover;
    } else {
      this.reset();
    }
  }

  private emitRequestChunked(body: Buffer, consumed: number): void {
    this.onRequest({
      method: this.method as string,
      path: this.path as string,
      protocol: this.protocol as string,
      headers: this.headers,
      body
    });
    const leftover = this.buffer.slice(consumed);
    this.reset();
    this.buffer = leftover;
  }
}

