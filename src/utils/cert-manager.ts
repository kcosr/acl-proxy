import forge from 'node-forge';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { logger } from './logger';

export interface CertificateManagerConfig {
  certsDir?: string;
  caKeyPath?: string;
  caCertPath?: string;
}

interface CachedCredentials {
  credentials: { cert: string; key: string };
  expiry: number;
}

export default class CertificateManager {
  private certsDir: string;
  private caKeyPath: string;
  private caCertPath: string;
  private dynamicCertsDir: string;
  private certCache: Map<string, CachedCredentials>;
  private caKey!: forge.pki.rsa.PrivateKey;
  private caCert!: forge.pki.Certificate;

  constructor(config: CertificateManagerConfig = {}) {
    const certsDir = config.certsDir || path.join(process.cwd(), 'certs');
    this.certsDir = path.resolve(certsDir);

    if (config.caKeyPath || config.caCertPath) {
      if (!config.caKeyPath || !config.caCertPath) {
        logger?.error?.(
          'Both caKeyPath and caCertPath must be specified together'
        );
        process.exit(1);
      }
      this.caKeyPath = path.resolve(config.caKeyPath);
      this.caCertPath = path.resolve(config.caCertPath);

      if (!fs.existsSync(this.caKeyPath)) {
        logger?.error?.(
          `Configured CA key not found at ${this.caKeyPath}`
        );
        process.exit(1);
      }
      if (!fs.existsSync(this.caCertPath)) {
        logger?.error?.(
          `Configured CA certificate not found at ${this.caCertPath}`
        );
        process.exit(1);
      }
    } else {
      this.caKeyPath = path.join(this.certsDir, 'ca-key.pem');
      this.caCertPath = path.join(this.certsDir, 'ca-cert.pem');
    }

    this.dynamicCertsDir = path.join(this.certsDir, 'dynamic');
    this.certCache = new Map();
    this.initializeCA();
    this.ensureDynamicCertsDir();
  }

  private ensureDynamicCertsDir(): void {
    if (!fs.existsSync(this.dynamicCertsDir)) {
      fs.mkdirSync(this.dynamicCertsDir, { recursive: true });
    }
  }

  private initializeCA(): void {
    try {
      if (fs.existsSync(this.caKeyPath) && fs.existsSync(this.caCertPath)) {
        const caKeyPem = fs.readFileSync(this.caKeyPath, 'utf8');
        const caCertPem = fs.readFileSync(this.caCertPath, 'utf8');
        this.caKey = forge.pki.privateKeyFromPem(caKeyPem) as forge.pki.rsa.PrivateKey;
        this.caCert = forge.pki.certificateFromPem(caCertPem);
        this.clearCache();
        return;
      }
      this.generateCA();
    } catch (err: any) {
      logger?.error?.(
        `Failed to initialize CA, regenerating: ${err.message}`
      );
      this.generateCA();
    }
  }

  private generateCA(): void {
    if (!fs.existsSync(this.certsDir)) {
      fs.mkdirSync(this.certsDir, { recursive: true });
    }
    const keys = forge.pki.rsa.generateKeyPair(4096);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 10
    );
    const attrs = [{ name: 'commonName', value: 'acl-proxy CA' }];
    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
      { name: 'basicConstraints', critical: true, cA: true, pathLenConstraint: 2 },
      {
        name: 'keyUsage',
        critical: true,
        keyCertSign: true,
        cRLSign: true,
        digitalSignature: true
      },
      { name: 'subjectKeyIdentifier' }
    ]);
    cert.sign(keys.privateKey, forge.md.sha384.create());
    fs.writeFileSync(this.caCertPath, forge.pki.certificateToPem(cert));
    fs.writeFileSync(
      this.caKeyPath,
      forge.pki.privateKeyToPem(keys.privateKey),
      { mode: 0o600 }
    );
    this.caKey = keys.privateKey;
    this.caCert = cert;
    this.clearCache();
  }

  generateCertificateForDomain(domain: string): { cert: string; key: string } {
    const cached = this.certCache.get(domain);
    if (cached && cached.expiry > Date.now()) {
      return cached.credentials;
    }
    const keys = forge.pki.rsa.generateKeyPair(3072);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keys.publicKey;
    {
      const b = crypto.randomBytes(16);
      b[0] &= 0x7f;
      if (b.every((x) => x === 0)) b[b.length - 1] = 1;
      cert.serialNumber = Buffer.from(b).toString('hex');
    }
    cert.validity.notBefore = new Date(Date.now() - 24 * 3600 * 1000);
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(
      cert.validity.notBefore.getFullYear() + 1
    );
    cert.setSubject([{ name: 'commonName', value: domain }]);
    cert.setIssuer(this.caCert.subject.attributes);
    cert.setExtensions([
      { name: 'basicConstraints', critical: true, cA: false },
      {
        name: 'keyUsage',
        critical: true,
        digitalSignature: true,
        keyEncipherment: true
      },
      { name: 'extKeyUsage', critical: true, serverAuth: true },
      {
        name: 'subjectAltName',
        critical: false,
        altNames: [{ type: 2, value: domain }]
      },
      { name: 'subjectKeyIdentifier' }
    ]);
    cert.sign(this.caKey, forge.md.sha384.create());
    const certPem = forge.pki.certificateToPem(cert);
    const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
    const caCertPem = forge.pki.certificateToPem(this.caCert);
    const chain = certPem + caCertPem;
    if (!fs.existsSync(this.dynamicCertsDir)) {
      fs.mkdirSync(this.dynamicCertsDir, { recursive: true });
    }
    fs.writeFileSync(path.join(this.dynamicCertsDir, `${domain}.crt`), certPem);
    fs.writeFileSync(path.join(this.dynamicCertsDir, `${domain}.key`), keyPem);
    fs.writeFileSync(
      path.join(this.dynamicCertsDir, `${domain}-chain.crt`),
      chain
    );
    const credentials = { cert: chain, key: keyPem };
    this.certCache.set(domain, {
      credentials,
      expiry: Date.now() + 24 * 3600 * 1000
    });
    return credentials;
  }

  clearCache(): void {
    this.certCache.clear();
  }

  getCACertificate(): string {
    return fs.readFileSync(this.caCertPath, 'utf8');
  }
}
