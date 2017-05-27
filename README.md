# An image resizer module for Nginx project.

### Nginx configuration:

```
    location xxx {
        use_image_resizer;
        image_resizer_types (jpg|jpeg|webp|png|bmp|tiff); /* supported image types */
        image_resizer_max_width 1000; /* max resize width */
        image_resizer_max_height 1000; /* max resize height */
    }
```

### usage:
for example, the source image url is http://www.example.com/data/example.jpg

> adjust image quality to be 90%

http://www.example.com/data/example_q90.jpg

> resize image, width:200 pixel, height:300 pixel

http://www.example.com/data/example_200x300.jpg 

> convert jpg format to be webp format

http://www.example.com/data/example.webp 

> resize image, width:200 pixel, height:300 pixel, and set quality to be 85%

http://www.example.com/data/example_200x300q85.jpg 

> resize image, width:200 pixel, height:300 pixel, and set quality to be 85%, and convert the format to be webp

http://www.example.com/data/example_200x300q85.webp 

- `_q[0-9]{1,2}`
    - image quality, value range [0, 99].

- `_[0-9]{1,4}[x|y|*][0-9]{1,4}`
     - the value range of `width` and `height` is specified by the configuration item `image_resizer_max_width`, `image_resizer_max_height`.

     - `resize` operation
        - `x`, keep original width/height ratio, fill the background with white color.
        - `*`, keep original width/height ratio, resize the image `height` to be specified value, and crop the extra pixels or fill the background with white color.
        - `y`, scale the image to be the specified `width, height` size.
