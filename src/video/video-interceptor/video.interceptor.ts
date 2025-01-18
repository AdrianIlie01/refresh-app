import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { diskStorage } from 'multer';
import { videoPath } from '../../shared/video-path';
import * as fs from 'fs';

@Injectable()
export class VideoInterceptor extends FileInterceptor('file', {
  limits: {
    fileSize: 50 * 1024 * 1024, // Dimensiunea maximă a fișierului video în bytes (50MB)
  },
  storage: diskStorage({
    destination: videoPath,
    filename: (req, file, callback) => {

      const nameWithoutExtension: string = file.originalname
        .split('.')
        .slice(0, -1)
        .join('.');

      let fileName = `${nameWithoutExtension}`;

      const videoExtensionRegex = /\.(mp4|avi|mov|mkv)$/; // Extensii de fișiere video acceptate

      // Verifică dacă fișierul are o extensie validă pentru video
      if (!videoExtensionRegex.test(file.originalname.toLowerCase())) {
        return callback(
          new HttpException(
            'Only video files are allowed!',
            HttpStatus.BAD_REQUEST,
          ),
          fileName,
        );
      }

      // Verifică dacă numele fișierului există deja în folder
      const files = fs.readdirSync(videoPath);
      const matchingFiles = files.filter((f) => f.includes(fileName));
      
      if (matchingFiles.length > 0) {
        // Adaugă un număr incremental la numele fișierului
        const lastIndex: number = matchingFiles.length - 1;
        const lastMatchingFile: string = matchingFiles[lastIndex];
        const lastFileNumber: number = parseInt(
          lastMatchingFile.replace(/.*_(\d+)\..*/, '$1'),
          10,
        );
        if (isNaN(lastFileNumber)) {
          fileName = `${fileName}_1`;
        } else {
          const newFileNumber = lastFileNumber + 1;
          fileName = `${fileName}_${newFileNumber}`;
        }
      }
      fileName += `.${file.originalname.split('.').pop()}`;
      file.filename = fileName;
      callback(null, fileName);
    },
  }),
}) {}
