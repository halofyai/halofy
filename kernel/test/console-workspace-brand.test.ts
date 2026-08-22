import { describe, expect, it } from "vitest";

import { paintOrganizationMark } from "../console/app.js";

type FakeImage = {
  alt: string;
  decoding: string;
  parentNode: FakeMark | null;
  src: string;
  listeners: Record<string, () => void>;
  addEventListener(type: string, listener: () => void): void;
  remove(): void;
};

type FakeMark = {
  children: FakeImage[];
  ownerDocument: { createElement(tag: string): FakeImage };
  textContent: string;
  appendChild(image: FakeImage): FakeImage;
};

function fakeMark(): FakeMark {
  const mark = {
    children: [] as FakeImage[],
    textContent: "",
    ownerDocument: {
      createElement() {
        const image: FakeImage = {
          alt: "",
          decoding: "",
          parentNode: null,
          src: "",
          listeners: {},
          addEventListener(type, listener) {
            this.listeners[type] = listener;
          },
          remove() {
            if (!this.parentNode) return;
            this.parentNode.children = this.parentNode.children.filter((child) => child !== this);
            this.parentNode = null;
          },
        };
        return image;
      },
    },
    appendChild(image: FakeImage) {
      image.parentNode = this;
      this.children.push(image);
      return image;
    },
  };
  return mark;
}

describe("workspace organization mark", () => {
  it("does not place initials behind a transparent organization image", () => {
    const mark = fakeMark();

    paintOrganizationMark(mark, "Halofy", "data:image/png;base64,logo");

    expect(mark.textContent).toBe("");
    expect(mark.children).toHaveLength(1);
    expect(mark.children[0]?.src).toBe("data:image/png;base64,logo");
  });

  it("restores initials only when the organization image fails", () => {
    const mark = fakeMark();

    paintOrganizationMark(mark, "Halofy", "data:image/png;base64,broken");
    mark.children[0]?.listeners.error?.();

    expect(mark.children).toHaveLength(0);
    expect(mark.textContent).toBe("HA");
  });
});
