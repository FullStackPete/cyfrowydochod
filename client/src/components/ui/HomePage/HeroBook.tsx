import { HeroBookType } from "@/types";
import HeroBookTile from "./HeroBookTile";
import TextDefault from "./textDefault";
import { Button } from "../button";
import LucideIcon from "./LucideIcon";
import Gradients from "@/components/ui/gradients";

type HeroBookProps = {
  book: HeroBookType;
};
function HeroBook({ book }: HeroBookProps) {
  return (
    <>
      <Gradients />
      <TextDefault title variant="default" center>
        {book.title}
      </TextDefault>
      <TextDefault variant="secondary" center>
        {book.subTitle}
      </TextDefault>
      <TextDefault variant="default" center>
        {book.firstText}
      </TextDefault>
      <TextDefault variant="default" center>
        {book.secondText}
      </TextDefault>

      {book.iconElements &&
        book.iconElements.map((element, index) => (
          <div key={index + element.icon} className="flex flex-col py-[2px] self-center">
            <div className="flex flex-row">
              {book.emojiGradientUrl && (
                <LucideIcon
                  className="mr-2"
                  style={{ stroke: book.emojiGradientUrl }}
                  name={element.icon}
                />
              )}
              <p>{element.text}</p>
            </div>
          </div>
        ))}
      <HeroBookTile
        imagePath={book.imagePath}
        bookTitle={book.title}
        price={book.price}
        author={book.author}
        bookFeatures={book.bookFeatures}
        gradient={book.gradient}
        textBlack={book.checksTableTextBlack}
      />
      <Button
        style={{ background: book.gradient }}
        className="self-center my-4"
      >
        Buy now!
      </Button>
    </>
  );
}

export default HeroBook;
