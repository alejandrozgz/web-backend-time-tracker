import fs from 'fs';
import path from 'path';

// Levels de logging
export enum LogLevel {
  INFO = 'INFO',
  WARN = 'WARN',
  ERROR = 'ERROR',
  DEBUG = 'DEBUG'
}

// Configuración del logger
const LOGS_DIR = path.join(process.cwd(), 'logs');
const MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB por archivo
const LOG_RETENTION_DAYS = 30; // Mantener logs de los últimos 30 días

// Asegurar que existe el directorio de logs
if (!fs.existsSync(LOGS_DIR)) {
  fs.mkdirSync(LOGS_DIR, { recursive: true });
}

// Obtener nombre del archivo de log para hoy
function getLogFileName(): string {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return path.join(LOGS_DIR, `${today}.log`);
}

// Formatear el mensaje de log
function formatLogMessage(level: LogLevel, message: string, metadata?: any): string {
  const timestamp = new Date().toISOString();
  const metadataStr = metadata ? ` | ${JSON.stringify(metadata)}` : '';
  return `[${timestamp}] [${level}] ${message}${metadataStr}\n`;
}

// Limpiar logs antiguos
function cleanOldLogs() {
  try {
    if (!fs.existsSync(LOGS_DIR)) {
      return;
    }

    const now = Date.now();
    const retentionMs = LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    const files = fs.readdirSync(LOGS_DIR);

    let deletedCount = 0;
    for (const file of files) {
      if (!file.endsWith('.log')) continue;

      const filePath = path.join(LOGS_DIR, file);
      const stats = fs.statSync(filePath);
      const fileAge = now - stats.mtime.getTime();

      // Eliminar si es más antiguo que el período de retención
      if (fileAge > retentionMs) {
        fs.unlinkSync(filePath);
        deletedCount++;
        console.log(`🗑️  Deleted old log file: ${file}`);
      }
    }

    if (deletedCount > 0) {
      console.log(`✅ Log cleanup: deleted ${deletedCount} old log file(s)`);
    }
  } catch (error) {
    console.error('Error cleaning old logs:', error);
  }
}

// Variable para controlar limpieza diaria
let lastCleanupDate: string | null = null;

// Escribir al archivo de log
function writeToFile(message: string) {
  try {
    const logFile = getLogFileName();
    const today = new Date().toISOString().split('T')[0];

    // Ejecutar limpieza una vez al día
    if (lastCleanupDate !== today) {
      cleanOldLogs();
      lastCleanupDate = today;
    }

    // Verificar tamaño del archivo antes de escribir
    if (fs.existsSync(logFile)) {
      const stats = fs.statSync(logFile);
      if (stats.size > MAX_LOG_SIZE) {
        // Rotar el archivo si es muy grande
        const timestamp = Date.now();
        const rotatedFile = logFile.replace('.log', `-${timestamp}.log`);
        fs.renameSync(logFile, rotatedFile);
      }
    }

    // Escribir al archivo (append)
    fs.appendFileSync(logFile, message, 'utf8');
  } catch (error) {
    // Si falla el logging a archivo, al menos log a consola
    console.error('Failed to write to log file:', error);
  }
}

// Clase Logger
class Logger {
  info(message: string, metadata?: any) {
    const formatted = formatLogMessage(LogLevel.INFO, message, metadata);
    console.log(formatted.trim());
    writeToFile(formatted);
  }

  warn(message: string, metadata?: any) {
    const formatted = formatLogMessage(LogLevel.WARN, message, metadata);
    console.warn(formatted.trim());
    writeToFile(formatted);
  }

  error(message: string, metadata?: any) {
    const formatted = formatLogMessage(LogLevel.ERROR, message, metadata);
    console.error(formatted.trim());
    writeToFile(formatted);
  }

  debug(message: string, metadata?: any) {
    const formatted = formatLogMessage(LogLevel.DEBUG, message, metadata);
    console.debug(formatted.trim());
    writeToFile(formatted);
  }

  // Log para requests HTTP
  http(method: string, url: string, status: number, duration?: number) {
    const message = `${method} ${url} ${status}`;
    const metadata = duration ? { duration: `${duration}ms` } : undefined;
    this.info(message, metadata);
  }
}

// Exportar instancia singleton
export const logger = new Logger();

// Funciones helper para listar y leer logs
export function listLogFiles(): string[] {
  try {
    if (!fs.existsSync(LOGS_DIR)) {
      return [];
    }

    const files = fs.readdirSync(LOGS_DIR);
    return files
      .filter(file => file.endsWith('.log'))
      .sort()
      .reverse(); // Más recientes primero
  } catch (error) {
    console.error('Error listing log files:', error);
    return [];
  }
}

export function readLogFile(filename: string): string | null {
  try {
    const filePath = path.join(LOGS_DIR, filename);

    // Validar que el archivo está en el directorio de logs (seguridad)
    const resolvedPath = path.resolve(filePath);
    const resolvedLogsDir = path.resolve(LOGS_DIR);
    if (!resolvedPath.startsWith(resolvedLogsDir)) {
      throw new Error('Invalid log file path');
    }

    if (!fs.existsSync(filePath)) {
      return null;
    }

    return fs.readFileSync(filePath, 'utf8');
  } catch (error) {
    console.error('Error reading log file:', error);
    return null;
  }
}

export function getLogFileStats(filename: string): { size: number; modified: Date } | null {
  try {
    const filePath = path.join(LOGS_DIR, filename);
    if (!fs.existsSync(filePath)) {
      return null;
    }

    const stats = fs.statSync(filePath);
    return {
      size: stats.size,
      modified: stats.mtime
    };
  } catch (error) {
    console.error('Error getting log file stats:', error);
    return null;
  }
}

// Función para ejecutar limpieza manual de logs
export function cleanupOldLogs(): { deleted: number; errors: string[] } {
  const result = { deleted: 0, errors: [] as string[] };

  try {
    if (!fs.existsSync(LOGS_DIR)) {
      return result;
    }

    const now = Date.now();
    const retentionMs = LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
    const files = fs.readdirSync(LOGS_DIR);

    for (const file of files) {
      if (!file.endsWith('.log')) continue;

      try {
        const filePath = path.join(LOGS_DIR, file);
        const stats = fs.statSync(filePath);
        const fileAge = now - stats.mtime.getTime();

        // Eliminar si es más antiguo que el período de retención
        if (fileAge > retentionMs) {
          fs.unlinkSync(filePath);
          result.deleted++;
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        result.errors.push(`Failed to delete ${file}: ${errorMsg}`);
      }
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    result.errors.push(`Failed to cleanup logs: ${errorMsg}`);
  }

  return result;
}

// Obtener información de retención
export function getLogRetentionInfo() {
  return {
    retentionDays: LOG_RETENTION_DAYS,
    maxFileSize: MAX_LOG_SIZE,
    logsDirectory: LOGS_DIR
  };
}
