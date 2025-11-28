import { NextRequest, NextResponse } from 'next/server';
import { withAdminAuth } from '@/middleware/adminAuth';
import { listLogFiles, readLogFile, getLogFileStats, getLogRetentionInfo, cleanupOldLogs } from '@/lib/logger';
import { logger } from '@/lib/logger';

// GET - List all log files or read a specific log file
async function GET(request: NextRequest) {
  try {
    const url = new URL(request.url);
    const filename = url.searchParams.get('filename');
    const lines = parseInt(url.searchParams.get('lines') || '1000');
    const filter = url.searchParams.get('filter'); // Filter by level (INFO, WARN, ERROR, DEBUG)

    // If filename is provided, read that specific file
    if (filename) {
      const content = readLogFile(filename);

      if (content === null) {
        return NextResponse.json({ error: 'Log file not found' }, { status: 404 });
      }

      // Split into lines and apply filters
      let logLines = content.split('\n').filter(line => line.trim() !== '');

      // Filter by level if specified
      if (filter) {
        logLines = logLines.filter(line => line.includes(`[${filter}]`));
      }

      // Limit number of lines (get last N lines)
      if (lines > 0 && logLines.length > lines) {
        logLines = logLines.slice(-lines);
      }

      const stats = getLogFileStats(filename);

      return NextResponse.json({
        filename,
        lines: logLines,
        totalLines: logLines.length,
        size: stats?.size || 0,
        modified: stats?.modified || new Date()
      });
    }

    // Otherwise, list all available log files
    const files = listLogFiles();
    const filesWithStats = files.map(file => {
      const stats = getLogFileStats(file);
      return {
        filename: file,
        size: stats?.size || 0,
        modified: stats?.modified || new Date(),
        date: file.replace('.log', '')
      };
    });

    // Include retention info
    const retentionInfo = getLogRetentionInfo();

    return NextResponse.json({
      files: filesWithStats,
      count: filesWithStats.length,
      retention: retentionInfo
    });

  } catch (error) {
    logger.error('Admin logs GET error', { error });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to retrieve logs',
      details: errorMessage
    }, { status: 500 });
  }
}

// POST - Cleanup old log files
async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const action = body.action;

    if (action === 'cleanup') {
      logger.info('Manual log cleanup triggered by admin');
      const result = cleanupOldLogs();

      if (result.errors.length > 0) {
        logger.warn('Log cleanup completed with errors', { deleted: result.deleted, errors: result.errors });
        return NextResponse.json({
          success: true,
          deleted: result.deleted,
          errors: result.errors,
          message: `Deleted ${result.deleted} file(s) with ${result.errors.length} error(s)`
        });
      }

      logger.info('Log cleanup completed successfully', { deleted: result.deleted });
      return NextResponse.json({
        success: true,
        deleted: result.deleted,
        message: `Successfully deleted ${result.deleted} old log file(s)`
      });
    }

    return NextResponse.json({ error: 'Invalid action' }, { status: 400 });

  } catch (error) {
    logger.error('Admin logs POST error', { error });
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';
    return NextResponse.json({
      error: 'Failed to process request',
      details: errorMessage
    }, { status: 500 });
  }
}

export { withAdminAuth as middleware };
export const GET_HANDLER = withAdminAuth(GET);
export const POST_HANDLER = withAdminAuth(POST);
export { GET_HANDLER as GET, POST_HANDLER as POST };
